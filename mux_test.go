package socker

import "testing"

func TestMatcheRegexp(t *testing.T) {
	matcher, err := MatchRegexp("127\\.0\\.\\d{1,3}\\.\\d{1,3}")
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
	matcher, err := MatchIPNet("127.0.0.0/16")
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
