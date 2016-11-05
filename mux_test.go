package socker

import (
	"sync"
	"testing"
	"time"
)

func TestMatcheRegexp(t *testing.T) {
	matcher, err := matchRegexp("127\\.0\\.\\d{1,3}\\.\\d{1,3}")
	if err != nil {
		t.Fatal(err)
	}
	type testCase struct {
		Addr  string
		Match bool
	}

	cases := []testCase{
		{Addr: "127.0.0.1", Match: true},
		{Addr: "127.0.1.1", Match: true},
		{Addr: "127.0.11.1", Match: true},
		{Addr: "127.0.111.1", Match: true},
		{Addr: "127.0.0.11", Match: true},
		{Addr: "127.0.0.111", Match: true},
		{Addr: "127.0.0a1", Match: false},
		{Addr: "127.0.011", Match: false},
	}

	for i, c := range cases {
		if matcher(c.Addr) != c.Match {
			t.Errorf("test case failed: %d", i)
		}
	}
}

func TestMatchIPNet(t *testing.T) {
	matcher, err := matchIPNet("127.0.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	type testCase struct {
		Addr  string
		Match bool
	}

	cases := []testCase{
		{Addr: "127.0.0.1", Match: true},
		{Addr: "127.0.1.1", Match: true},
		{Addr: "127.0.11.1", Match: true},
		{Addr: "127.0.111.1", Match: true},
		{Addr: "127.0.0.11", Match: true},
		{Addr: "127.0.0.111", Match: true},
		{Addr: "127.0.0a1", Match: false},
		{Addr: "127.0.011", Match: false},
		{Addr: "127.1.2.3:22", Match: false},
		{Addr: "127.0.2.3:22", Match: true},
	}

	for i, c := range cases {
		if matcher(c.Addr) != c.Match {
			t.Errorf("test case failed: %d", i)
		}
	}
}

func TestPriority(t *testing.T) {
	gates := map[string]string{
		"ipnet:127.0.0.0/16":       "ipnet",
		"plain:127.0.0.1:22":       "plain",
		"regexp:127.0.0.\\d+:\\d+": "regexp",
	}
	m, err := NewMux(MuxAuth{
		AgentGates: gates,
	})
	if err != nil {
		t.Fatal(err)
	}
	if m.AgentGate("127.0.0.1:22") != "plain" {
		t.Fatal("match failed")
	}
	if m.AgentGate("127.0.0.2:22") != "regexp" {
		t.Fatal("match failed")
	}
	if m.AgentGate("127.0.1.3:22") != "ipnet" {
		t.Fatal("match failed")
	}
}

var auth = &Auth{User: "root", Password: "root"}

func TestGate(t *testing.T) {
	gate, err := Dial("10.0.1.1", auth)
	if err != nil {
		t.Fatal("dial agent failed:", err)
	}
	defer gate.Close()

	testSSH(t, gate)
}

func TestSSH(t *testing.T) {
	testSSH(t, nil)
}

func testSSH(t *testing.T, gate *SSH) {
	agent, err := Dial("192.168.1.1", auth, gate)
	if err != nil {
		t.Fatal("dial agent failed:", err)
	}
	defer agent.Close()

	testAgent(t, agent)
}

func testAgent(t *testing.T, agent *SSH) {
	agent.ReserveCmdOutput(nil).ReserveError(nil)

	agent.Rcmd("ls -al ~/")
	agent.Put("~/local", "~/remote")
	agent.Get("~/remote", "~/local")

	agent.RcmdBg("sleep 30", "sleep.out", "sleep.err")

	t.Log(string(agent.CmdOutput()))
	err := agent.Error()
	if err != nil {
		t.Error(err)
	}
}

func TestMux(t *testing.T) {
	var (
		netFoo  = "netFoo"
		gateFoo = "10.0.1.1"
		authFoo = &Auth{User: "foo", Password: "foo"}
		netBar  = "netBar"
		authBar = &Auth{User: "bar", Password: "bar"}
		gateBar = "10.0.2.1"
	)

	auth := MuxAuth{
		AuthMethods: map[string]*Auth{
			netFoo: authFoo,
			netBar: authBar,
		},

		DefaultAuth: netFoo,
		AgentGates: map[string]string{
			"ipnet:192.168.1.0/24": gateFoo + ":22",
			"ipnet:192.168.2.0/24": gateBar + ":22",
		},
		AgentAuths: map[string]string{
			"plain:" + gateFoo:     netFoo,
			"ipnet:192.168.1.0/24": netFoo,
			"plain:" + gateBar:     netBar,
			"ipnet:192.168.2.0/24": netBar,
		},
	}

	mux, err := NewMux(auth)
	if err != nil {
		t.Fatal(err)
	}

	type testCase struct {
		Addr  string
		Gate  string
		Auth  *Auth
		Error error
	}
	cases := []testCase{
		{Addr: gateFoo, Gate: "", Auth: authFoo},
		{Addr: "192.168.1.1", Gate: gateFoo, Auth: authFoo},
		{Addr: "192.168.1.255", Gate: gateFoo, Auth: authFoo},

		{Addr: gateBar, Gate: "", Auth: authBar},
		{Addr: "192.168.2.1", Gate: gateBar, Auth: authBar},
		{Addr: "192.168.2.255", Gate: gateBar, Auth: authBar},

		{Addr: "192.168.3.1", Gate: "", Auth: authFoo, Error: nil},
	}

	for _, c := range cases {
		if got := mux.AgentGate(c.Addr); got != c.Gate {
			t.Errorf("gate match failed %s: expect %s, got %s", c.Addr, c.Gate, got)
		}
		got, gotError := mux.AgentAuth(c.Addr)
		if got != c.Auth {
			t.Errorf("auth match failed %s", c.Addr)
		}
		if gotError != c.Error {
			t.Errorf("auth error match failed %s: expect %v, got %v", c.Addr, c.Error, gotError)
		}
	}
	defer mux.Close()

	mux.Keepalive(time.Second * 10)

	var wg sync.WaitGroup
	for _, addr := range []string{"192.168.1.2:22", "192.168.2.2:22"} {
		agent, err := mux.Dial(addr)
		if err != nil {
			t.Error("dial agent failed:", err)
			break
		}

		wg.Add(1)
		go func() {
			defer agent.Close()
			defer wg.Done()

			testAgent(t, agent)
		}()
	}

	wg.Wait()
}

func TestLocalOnly(t *testing.T) {
	local := LocalOnly()

	out, err := local.TmpLcd("/").Lcmd("ls $DIR", "DIR=`pwd`")
	t.Log(string(out), err)
}
