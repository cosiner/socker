# Socker

Socker is a library for [Go](https://golang.org) to simplify the use of SSH, support keepalive and multiplexing.
Inspired by [Fabric](http://www.fabfile.org) for Python.

# Documentation
Documentation can be found at [Godoc](https://godoc.org/github.com/cosiner/socker)

# Example
```Go
var sshConfig = (&Auth{User: "root", Password: "root"}).MustSSHConfig()

func TestGate(t *testing.T) {
	gate, err := Dial("10.0.1.1", sshConfig)
	if err != nil {
		t.Error("dial agent failed:", err)
	}
	defer gate.Close()

	testSSH(t, gate)
}

func TestSSH(t *testing.T) {
	testSSH(t, nil)
}

func testSSH(t *testing.T, gate *SSH) {
	agent, err := Dial("192.168.1.1", sshConfig, gate)
	if err != nil {
		t.Error("dial agent failed:", err)
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
		KeepAliveSeconds: 30,
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
```

# LICENSE
MIT.
