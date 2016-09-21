package socker

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
)

type (
	Matcher        func(addr string) bool
	MatcherBuilder func(string) (Matcher, error)
)

var (
	builders          = make(map[string]MatcherBuilder)
	builderPriorities = make(map[string]int)
	buildersMu        sync.RWMutex
)

func init() {
	RegisterMatchBuilder("plain", matchPlain, 100)
	RegisterMatchBuilder("regexp", matchRegexp, 50)
	RegisterMatchBuilder("ipnet", matchIPNet, 0)
}

func RegisterMatchBuilder(name string, builder MatcherBuilder, priority int) (replaced bool) {
	if builder == nil {
		panic("socker: Register builder is nil")
	}

	buildersMu.Lock()
	_, has := builders[name]
	builders[name] = builder
	builderPriorities[name] = priority
	buildersMu.Unlock()
	return has
}

func ResetMatcherPriority(name string, priority int) {
	buildersMu.Lock()
	_, has := builders[name]
	if has {
		builderPriorities[name] = priority
	}
	buildersMu.Unlock()
}

func getMatcherBuilder(name string) (MatcherBuilder, int) {
	buildersMu.RLock()
	builder := builders[name]
	priority := builderPriorities[name]
	buildersMu.RUnlock()
	return builder, priority
}

func createMatcher(addr string) (Matcher, int, error) {
	var (
		builderName string
		matchAddr   string
	)
	index := strings.IndexByte(addr, ':')
	if index < 0 {
		builderName = "plain"
		matchAddr = addr
	} else {
		builderName = addr[:index]
		matchAddr = addr[index+1:]
	}

	builder, priority := getMatcherBuilder(builderName)
	if builder == nil {
		return nil, 0, fmt.Errorf("builder %s is not registered", builderName)
	}
	matcher, err := builder(matchAddr)
	if err != nil {
		return nil, 0, fmt.Errorf("create matcher for addr %s failed: %s", addr, err.Error())
	}
	return matcher, priority, nil
}

func matchRegexp(addr string) (Matcher, error) {
	r, err := regexp.Compile(addr)
	if err != nil {
		return nil, err
	}
	return func(addr string) bool {
		return r.MatchString(addr)
	}, nil
}

func matchIPNet(cidr string) (Matcher, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return func(addr string) bool {
		if strings.IndexByte(addr, ':') >= 0 {
			host, _, err := net.SplitHostPort(addr)
			if err != nil || host == "" {
				return false
			}
			addr = host
		}

		ip := net.ParseIP(addr)
		if ip == nil {
			return false
		}
		return ipnet.Contains(ip)
	}, nil
}

func matchPlain(addr string) (Matcher, error) {
	return func(dst string) bool {
		return addr == dst
	}, nil
}
