package socker

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	ErrMuxClosed    = errors.New("mux has been closed")
	ErrNoAuthMethod = errors.New("no auth method can be applied to agent")
)

// MuxAuth holds auth and gate configs
type MuxAuth struct {
	// AuthMethods holds all auth methods to destination host. The key can be any
	// string.
	AuthMethods map[string]*Auth

	// DefaultAuth is the default auth method, it must be a key in AuthMethods field,
	// only used if no auth method is matched for destination, can be empty.
	DefaultAuth string
	// AgentAuths define the rule which auth method is used to connect to destination host.
	// The key is the format of "matcher:matchor", the value must be a key in
	// AuthMethods field.
	AgentAuths map[string]string
	// AgentGates define the rule which gate is used to connect to destination host.
	// The key is the format of "matcher:matchor", the value must be an valid "host:port"
	// like string.
	AgentGates map[string]string

	// KeepAliveSeconds limit the lifetime of idle ssh connection, default is 300.
	KeepAliveSeconds int
}

// ApplyDefaultHostCheck apply the checking function or ssh.InsecureIgnoreHostKey to each Auth instance.
func (a *MuxAuth) ApplyDefaultHostCheck(check ssh.HostKeyCallback) {
	if check == nil {
		check = ssh.InsecureIgnoreHostKey()
	}
	for _, auth := range a.AuthMethods {
		if auth.HostKeyCheck == nil {
			auth.HostKeyCheck = check
		}
	}
}

func (a *MuxAuth) checkAuth(id string, auth *Auth) error {
	_, err := auth.SSHConfig()
	if err != nil {
		if id == "" {
			return err
		}
		return fmt.Errorf("auth method %s is invalid: %s", id, err.Error())
	}
	return nil
}

func (a *MuxAuth) Validate() error {
	for id, auth := range a.AuthMethods {
		err := a.checkAuth(id, auth)
		if err != nil {
			return err
		}
	}

	if a.DefaultAuth != "" && a.AuthMethods[a.DefaultAuth] == nil {
		return errors.New("default auth method is not exist")
	}
	for _, id := range a.AgentAuths {
		if a.AuthMethods[id] == nil {
			return fmt.Errorf("agent auth method %s is not exist", id)
		}
	}
	return nil
}

type priorityMatcher struct {
	Priority int
	Matcher
	Value string
}

type byPriority []priorityMatcher

func (b byPriority) Len() int {
	return len(b)
}

func (b byPriority) Less(i, j int) bool {
	return b[i].Priority > b[j].Priority
}

func (b byPriority) Swap(i, j int) {
	b[i], b[j] = b[j], b[i]
}

type Mux struct {
	closed int32

	authMethods   map[string]*Auth
	defaultAuthID string
	agents        []priorityMatcher
	gates         []priorityMatcher

	sshsMu sync.RWMutex
	sshs   map[string]*SSH

	aliveChan chan struct{}
}

func NewMux(auth MuxAuth) (*Mux, error) {
	auth.ApplyDefaultHostCheck(nil)

	err := auth.Validate()
	if err != nil {
		return nil, err
	}
	var m Mux

	m.authMethods = make(map[string]*Auth)
	for id, auth := range auth.AuthMethods {
		if id != "" && auth != nil {
			m.authMethods[id] = auth
		}
	}

	m.gates = make([]priorityMatcher, 0, len(auth.AgentGates))
	for addr, gate := range auth.AgentGates {
		if addr != "" && gate != "" {
			matcher, priority, err := createMatcher(SplitRuleAndAddr(addr))
			if err != nil {
				return nil, err
			}
			m.gates = append(m.gates, priorityMatcher{
				Matcher:  matcher,
				Priority: priority,
				Value:    gate,
			})
		}
	}
	sort.Sort(byPriority(m.gates))

	m.defaultAuthID = auth.DefaultAuth
	m.agents = make([]priorityMatcher, 0, len(auth.AgentAuths))
	for addr, authID := range auth.AgentAuths {
		if addr != "" && authID != "" {
			matcher, priority, err := createMatcher(SplitRuleAndAddr(addr))
			if err != nil {
				return nil, err
			}

			m.agents = append(m.agents, priorityMatcher{
				Matcher:  matcher,
				Priority: priority,
				Value:    authID,
			})
		}
	}
	sort.Sort(byPriority(m.agents))

	m.sshs = make(map[string]*SSH)

	const defaultKeepAliveSeconds = 300
	if auth.KeepAliveSeconds <= 0 {
		auth.KeepAliveSeconds = defaultKeepAliveSeconds
	}
	m.keepAlive(time.Duration(auth.KeepAliveSeconds) * defaultKeepAliveSeconds)
	return &m, nil
}

func (m *Mux) match(matchers []priorityMatcher, addr string) string {
	var val string
	for i := range matchers {
		if matchers[i].Matcher(addr) {
			val = matchers[i].Value
			break
		}
	}
	return val
}

func (m *Mux) AgentGate(addr string) string {
	gate := m.match(m.gates, addr)
	return gate
}

func (m *Mux) AgentAuth(addr string) (*Auth, error) {
	authID := m.match(m.agents, addr)
	if authID == "" {
		authID = m.defaultAuthID
	}

	if authID != "" {
		return m.authMethods[authID], nil
	}
	return nil, ErrNoAuthMethod
}

func (m *Mux) keepAlive(idle time.Duration) {
	m.aliveChan = make(chan struct{}, 1)
	go func() {
		var (
			timer    = time.NewTimer(idle)
			timerNil bool
		)

		for {
			select {
			case now := <-timer.C:
				if m.checkAlive(now, idle) {
					timer.Reset(idle)
				} else {
					timerNil = true
				}
			case _, ok := <-m.aliveChan:
				if !ok {
					if timer != nil {
						timer.Stop()
					}
					return
				}

				if timerNil {
					timer = time.NewTimer(idle)
					timerNil = false
				}
			}
		}
	}()
}

func (m *Mux) checkAlive(now time.Time, idle time.Duration) bool {
	var (
		sshs     []*SSH
		hasAlive bool
	)
	m.sshsMu.Lock()
	for addr, s := range m.sshs {
		openAt, refs := s.Status()
		if refs <= 0 && now.Sub(openAt) >= idle {
			sshs = append(sshs, s)
			delete(m.sshs, addr)
		} else {
			hasAlive = true
		}
	}
	m.sshsMu.Unlock()
	for _, s := range sshs {
		s.Close()
	}
	return hasAlive
}

func (m *Mux) markClosed() bool {
	return atomic.CompareAndSwapInt32(&m.closed, 0, 1)
}

func (m *Mux) isClosed() bool {
	return atomic.LoadInt32(&m.closed) == 1
}

func (m *Mux) Close() error {
	if !m.markClosed() {
		return nil
	}
	if m.aliveChan != nil {
		close(m.aliveChan)
	}
	m.sshsMu.Lock()
	for _, s := range m.sshs {
		s.Close()
	}
	m.sshsMu.Unlock()
	return nil
}

func (m *Mux) Dial(addr string) (*SSH, error) {
	if m.isClosed() {
		return nil, ErrMuxClosed
	}

	var (
		agent *SSH
		gate  *SSH
		has   bool

		err error
	)

	gateAddr := m.AgentGate(addr)
	m.sshsMu.RLock()
	agent, has = m.sshs[addr]
	if !has {
		if gateAddr != "" {
			gate, has = m.sshs[gateAddr]
			if has {
				gate = gate.NopClose()
			}
		}
	} else {
		agent = agent.NopClose()
	}
	m.sshsMu.RUnlock()
	if agent != nil {
		return agent, nil
	}

	if gate == nil && gateAddr != "" {
		gate, err = m.Dial(gateAddr)
		if err != nil {
			return nil, err
		}
	}
	if gate != nil {
		defer gate.Close()
	}

	return m.dial(addr, gate)
}

func (m *Mux) dial(addr string, gate *SSH) (*SSH, error) {
	auth, err := m.AgentAuth(addr)
	if err != nil {
		return nil, err
	}

	agent, err := Dial(addr, auth, gate)
	if err != nil {
		return nil, err
	}

	m.sshsMu.Lock()
	tmp, has := m.sshs[addr]
	if has {
		agent, tmp = tmp, agent
	} else {
		m.sshs[addr] = agent
		if m.aliveChan != nil && !m.isClosed() {
			select {
			case m.aliveChan <- struct{}{}:
			default:
			}
		}
	}
	agent = agent.NopClose()
	m.sshsMu.Unlock()

	if tmp != nil {
		tmp.Close()
	}
	return agent, nil
}
