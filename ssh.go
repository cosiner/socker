package socker

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

var (
	ErrIsDir = errors.New("destination is directory")
)

type Auth struct {
	User           string
	Password       string
	PrivateKey     string
	PrivateKeyFile string

	config *ssh.ClientConfig
}

func (a *Auth) privateKeyMethod(pemBytes []byte) (ssh.AuthMethod, error) {
	sign, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, err
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
		fd, err := os.Open(a.PrivateKeyFile)
		if err != nil {
			return nil, err
		}
		defer fd.Close()
		pemBytes, err := ioutil.ReadAll(fd)
		if err != nil {
			return nil, err
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
	a.config = config
	return a.config, nil
}

type SSH struct {
	nopClose bool

	conn *ssh.Client
	sftp *sftp.Client

	remoteFs Fs
	localFs  Fs

	rcwd string
	lcwd string

	gate   *SSH
	openAt time.Time
	_refs  *int32
}

func NewSSH(client *ssh.Client, gate *SSH) (*SSH, error) {
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return nil, err
	}
	var refs int32
	return &SSH{
		conn:     client,
		sftp:     sftpClient,
		remoteFs: NewFsSftp(sftpClient),
		localFs:  FsLocal{},

		gate:   gate,
		openAt: time.Now(),
		_refs:  &refs,
	}, nil
}

func Dial(addr string, config *ssh.ClientConfig, gate ...*SSH) (*SSH, error) {
	if len(gate) > 0 && gate[0] != nil {
		return gate[0].Dial(addr, config)
	}

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, err
	}

	s, err := NewSSH(client, nil)
	if err != nil {
		client.Close()
		return nil, err
	}
	return s, nil
}

func (s *SSH) DialConn(net, addr string) (net.Conn, error) {
	return s.conn.Dial(net, addr)
}

func (s *SSH) Dial(addr string, config *ssh.ClientConfig) (*SSH, error) {
	conn, err := s.conn.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		conn.Close()
		return nil, err
	}

	client := ssh.NewClient(c, chans, reqs)
	ssh, err := NewSSH(client, s.NopClose())
	if err != nil {
		client.Close()
		return nil, err
	}
	return ssh, nil
}

func (s *SSH) incrRefs() int32 {
	return atomic.AddInt32(s._refs, 1)
}

func (s *SSH) decrRefs() int32 {
	return atomic.AddInt32(s._refs, -1)
}

func (s *SSH) Status() (openAt time.Time, refs int32) {
	return s.openAt, atomic.LoadInt32(s._refs)
}

func (s *SSH) Close() {
	if s.nopClose {
		s.decrRefs()
		return
	}
	if s.gate != nil {
		s.gate.decrRefs()
	}
	s.sftp.Close()
	s.conn.Close()
}

func (s *SSH) NopClose() *SSH {
	s.incrRefs()
	if s.nopClose {
		return s
	}
	ns := *s
	ns.nopClose = true
	return &ns
}

func (s *SSH) checkIsDir(fd File, stat os.FileInfo, err error) (File, error) {
	if err != nil {
		err = nil
	} else if stat.IsDir() {
		fd.Close()
		err = ErrIsDir
	}
	return fd, err
}

func (s *SSH) openFile(fs Fs, path string, flag int, mode os.FileMode) (File, error) {
	fd, err := fs.OpenFile(path, flag, mode)
	if err != nil {
		return nil, err
	}
	stat, err := fd.Stat()
	return s.checkIsDir(fd, stat, err)
}

func (s *SSH) Rcmd(cmd string, env ...string) ([]byte, error) {
	sess, err := s.conn.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	for _, e := range env {
		secs := strings.SplitN(e, "=", 2)
		var k, v string
		if len(secs) > 0 {
			k = secs[0]
		}
		if len(secs) > 1 {
			v = secs[1]
		}
		err = sess.Setenv(k, v)
		if err != nil {
			return nil, err
		}
	}
	return sess.CombinedOutput(s.rcmd(cmd))
}

func (s *SSH) Lcmd(cmd string, env ...string) ([]byte, error) {
	c := exec.Command("sh", "-c", s.lcmd(cmd))
	if len(env) > 0 {
		c.Env = append(c.Env, env...)
	}
	return c.CombinedOutput()
}

func (s *SSH) sync(fs, remoteFs Fs, path, remotePath string) error {
	fd, err := fs.Open(path)
	if err != nil {
		return err
	}
	defer fd.Close()

	info, err := fs.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return s.syncFile(remoteFs, remotePath, fd, info)
	}

	dirnames, err := fd.Readdir(-1)
	if err != nil {
		return err
	}
	for _, dirname := range dirnames {
		name := dirname.Name()
		err = s.sync(fs, remoteFs, filepath.Join(path, name), filepath.Join(remotePath, name))
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *SSH) syncFile(rfs Fs, rpath string, fd io.Reader, stat os.FileInfo) error {
	err := rfs.Remove(rpath)

	if err != nil && !rfs.IsNotExist(err) {
		return err
	}

	dir, _ := filepath.Split(rpath)
	dir = filepath.FromSlash(dir)

	if dir != "" {
		err = rfs.MkdirAll(dir, 0755)
		if err != nil {
			return err
		}
	}

	rfd, err := s.openFile(rfs, rpath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, stat.Mode())
	if err != nil {
		return err
	}
	defer rfd.Close()

	_, err = io.Copy(rfd, fd)
	if err == io.EOF {
		err = nil
	}
	return err
}

func (s *SSH) writeFile(fs Fs, path string, data []byte) error {
	fd, err := s.openFile(fs, path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer fd.Close()
	_, err = fd.Write(data)
	return err
}

func (s *SSH) readFile(fs Fs, path string) ([]byte, error) {
	fd, err := s.openFile(fs, path, os.O_RDONLY, 0644)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	return ioutil.ReadAll(fd)
}

func (s *SSH) LwriteFile(path string, data []byte) error {
	return s.writeFile(s.localFs, s.lpath(path), data)
}

func (s *SSH) LreadFile(path string) ([]byte, error) {
	return s.readFile(s.localFs, s.lpath(path))
}

func (s *SSH) RwriteFile(path string, data []byte) error {
	return s.writeFile(s.remoteFs, s.rpath(path), data)
}

func (s *SSH) RreadFile(path string) ([]byte, error) {
	return s.readFile(s.remoteFs, s.rpath(path))
}

type byName []os.FileInfo

func (f byName) Len() int           { return len(f) }
func (f byName) Less(i, j int) bool { return f[i].Name() < f[j].Name() }
func (f byName) Swap(i, j int)      { f[i], f[j] = f[j], f[i] }

func (s *SSH) readdir(fs Fs, path string, n int) ([]os.FileInfo, error) {
	f, err := fs.Open(path)
	if err != nil {
		return nil, err
	}
	list, err := f.Readdir(n)
	f.Close()
	if err != nil {
		return nil, err
	}
	sort.Sort(byName(list))
	return list, nil
}

func (s *SSH) Lreaddir(path string, n int) ([]os.FileInfo, error) {
	return s.readdir(s.localFs, s.lpath(path), n)
}

func (s *SSH) Rreaddir(path string, n int) ([]os.FileInfo, error) {
	return s.readdir(s.remoteFs, s.rpath(path), n)
}

func (s *SSH) Put(path, remotePath string) error {
	return s.sync(s.localFs, s.remoteFs, s.lpath(path), s.rpath(remotePath))
}

func (s *SSH) Get(remotePath, path string) error {
	return s.sync(s.remoteFs, s.localFs, s.rpath(remotePath), s.lpath(path))
}

func (s *SSH) Rremove(path string, recursive bool) error {
	return s.remove(s.remoteFs, s.rpath(path), recursive)
}

func (s *SSH) Lremove(path string, recursive bool) error {
	return s.remove(s.localFs, s.lpath(path), recursive)
}

func (s *SSH) remove(fs Fs, path string, recursive bool) error {
	if recursive {
		return fs.RemoveAll(path)
	}
	return fs.Remove(path)
}

func (s *SSH) Rexists(path string) (bool, error) {
	return s.exists(s.remoteFs, s.rpath(path))
}

func (s *SSH) Lexists(path string) (bool, error) {
	return s.exists(s.localFs, s.lpath(path))
}

func (s *SSH) exists(fs Fs, path string) (bool, error) {
	_, err := fs.Stat(path)
	if err != nil {
		if fs.IsNotExist(err) {
			err = nil
		}
		return false, err
	}
	return true, nil
}

func (s *SSH) rcmd(cmd string) string {
	return s.cmd(s.rcwd, cmd)
}

func (s *SSH) lcmd(cmd string) string {
	return s.cmd(s.lcwd, cmd)
}

func (s *SSH) cmd(cwd, cmd string) string {
	if cwd == "" {
		return cmd
	}
	return fmt.Sprintf("cd %s && %s", cwd, cmd)
}

func (s *SSH) Rcd(cwd string) {
	s.rcwd = s.rpath(cwd)
}

func (s *SSH) TmpRcd(cwd string) *SSH {
	ns := *s
	ns.Rcd(cwd)
	return &ns
}

func (s *SSH) Lcd(cwd string) {
	s.lcwd = s.lpath(cwd)
}

func (s *SSH) TmpLcd(cwd string) *SSH {
	ns := *s
	ns.Lcd(cwd)
	return &ns
}

func (s *SSH) rpath(path string) string {
	return s.path(s.rcwd, path)
}

func (s *SSH) lpath(path string) string {
	return s.path(s.lcwd, path)
}

func (s *SSH) path(base, cwd string) string {
	if filepath.IsAbs(cwd) {
		return cwd
	}
	return filepath.Join(base, cwd)
}
