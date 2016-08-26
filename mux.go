package socker

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrMuxClosed    = errors.New("mux has been closed")
	ErrNoAuthMethod = errors.New("no auth method can be applied to agent")
)

type MuxAuth struct {
	// <ID, Auth>
	AuthMethods map[string]*Auth

	// AuthID
	DefaultAuth string
	// <Matcher, AuthID>
	AgentAuths map[string]string
	// <Matcher, GateAddr>
	AgentGates map[string]string
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

type muxAuth struct {
	Matcher
	AuthId string
}

type muxGate struct {
	Matcher
	GateAddr string
}

type Mux struct {
	closed int32

	authMethods   map[string]*Auth
	defaultAuthId string
	agents        []muxAuth
	gates         []muxGate

	sshsMu sync.RWMutex
	sshs   map[string]*SSH

	aliveChan chan struct{}
}

func NewMux(auth MuxAuth) (*Mux, error) {
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

	m.gates = make([]muxGate, 0, len(auth.AgentGates))
	for addr, gate := range auth.AgentGates {
		if addr != "" && gate != "" {
			matcher, err := createMatcher(addr)
			if err != nil {
				return nil, err
			}
			m.gates = append(m.gates, muxGate{
				Matcher:  matcher,
				GateAddr: gate,
			})
		}
	}

	m.defaultAuthId = auth.DefaultAuth
	m.agents = make([]muxAuth, 0, len(auth.AgentAuths))
	for addr, authId := range auth.AgentAuths {
		if addr != "" && authId != "" {
			matcher, err := createMatcher(addr)
			if err != nil {
				return nil, err
			}

			m.agents = append(m.agents, muxAuth{
				Matcher: matcher,
				AuthId:  authId,
			})
		}
	}

	m.sshs = make(map[string]*SSH)
	return &m, nil
}

func (m *Mux) AgentGate(addr string) string {
	var gate string
	for i := range m.gates {
		if m.gates[i].Matcher(addr) {
			gate = m.gates[i].GateAddr
			break
		}
	}
	return gate
}

func (m *Mux) AgentAuth(addr string) (*Auth, error) {
	var authId string
	for i := range m.agents {
		if m.agents[i].Matcher(addr) {
			authId = m.agents[i].AuthId
			break
		}
	}
	if authId == "" {
		authId = m.defaultAuthId
	}

	if authId != "" {
		return m.authMethods[authId], nil
	}
	return nil, ErrNoAuthMethod
}

func (m *Mux) Keepalive(idle time.Duration) {
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
		gate, err = m.dial(gateAddr, nil)
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

	agent, err := Dial(addr, auth.MustSSHConfig(), gate)
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
