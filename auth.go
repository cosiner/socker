package socker

import (
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	ErrIsDir = errors.New("destination is directory")

	CopyBufferSize int64 = 1024 * 1024
	CmdSeperator         = "&&" // or ;
)

type Auth struct {
	User           string
	Password       string
	PrivateKey     string
	PrivateKeyFile string

	HostKeyCheck ssh.HostKeyCallback

	TimeoutMs  int
	MaxSession int

	config *ssh.ClientConfig
}

func (a *Auth) privateKeyMethod(pemBytes []byte) (ssh.AuthMethod, error) {
	sign, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %s", err.Error())
	}
	return ssh.PublicKeys(sign), nil
}

func (a *Auth) MustSSHConfig() *ssh.ClientConfig {
	cfg, err := a.SSHConfig()
	if err != nil {
		panic(err)
	}
	return cfg
}

func (a *Auth) SSHConfig() (*ssh.ClientConfig, error) {
	if a.config != nil {
		return a.config, nil
	}

	config := &ssh.ClientConfig{}
	config.User = a.User
	if a.Password != "" {
		method := ssh.Password(a.Password)
		config.Auth = append(config.Auth, method)
	}
	if len(a.PrivateKey) > 0 {
		method, err := a.privateKeyMethod([]byte(a.PrivateKey))
		if err != nil {
			return nil, err
		}
		config.Auth = append(config.Auth, method)
	}
	if a.PrivateKeyFile != "" {
		pemBytes, err := ioutil.ReadFile(a.PrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("invalid private key file: %s", err.Error())
		}
		method, err := a.privateKeyMethod(pemBytes)
		if err != nil {
			return nil, err
		}
		config.Auth = append(config.Auth, method)
	}
	if len(config.Auth) == 0 {
		return nil, errors.New("no auth method supplied")
	}
	config.Timeout = time.Duration(a.TimeoutMs) * time.Millisecond
	config.HostKeyCallback = a.HostKeyCheck
	if config.HostKeyCallback == nil {
		config.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	}
	a.config = config
	return a.config, nil
}
