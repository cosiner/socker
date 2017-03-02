package socker

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
)

type (
	Matcher   func(addr string) bool
	MatchRule func(string) (Matcher, error)
)

var (
	rules          = make(map[string]MatchRule)
	rulePriorities = make(map[string]int)
	rulesMu        sync.RWMutex
)

const (
	RulePlain  = "plain"
	RuleRegexp = "regexp"
	RuleIpnet  = "ipnet"
)

func init() {
	RegisterMatchRule(RulePlain, matchPlain, 100)
	RegisterMatchRule(RuleRegexp, matchRegexp, 50)
	RegisterMatchRule(RuleIpnet, matchIPNet, 0)
}

func RegisterMatchRule(name string, rule MatchRule, priority int) (replaced bool) {
	if rule == nil {
		panic("socker: match rule is nil")
	}

	rulesMu.Lock()
	_, has := rules[name]
	rules[name] = rule
	rulePriorities[name] = priority
	rulesMu.Unlock()
	return has
}

func ResetRulePriority(name string, priority int) {
	rulesMu.Lock()
	_, has := rules[name]
	if has {
		rulePriorities[name] = priority
	}
	rulesMu.Unlock()
}

func SplitRuleAndAddr(s string) (rule, addr string) {
	index := strings.IndexByte(s, ':')
	if index < 0 {
		return RulePlain, s
	}
	return s[:index], s[index+1:]
}

func JoinRuleAndAddr(rule, addr string) string {
	return rule + ":" + addr
}

func getMatchRule(name string) (MatchRule, int) {
	rulesMu.RLock()
	rule := rules[name]
	priority := rulePriorities[name]
	rulesMu.RUnlock()
	return rule, priority
}

func createMatcher(ruleName, addr string) (Matcher, int, error) {
	rule, priority := getMatchRule(ruleName)
	if rule == nil {
		return nil, 0, fmt.Errorf("rule %s is not registered", ruleName)
	}
	matcher, err := rule(addr)
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
