package socker

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/pkg/sftp"
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

var ErrConnClosed = errors.New("connection closed")

type SSH struct {
	err       *error
	cmdOutput *bytes.Buffer

	nopClose bool

	conn        *ssh.Client
	sftp        *sftp.Client
	sessionPool *sessionPool

	remoteFs Fs
	localFs  Fs

	rcwd string
	lcwd string

	gate   *SSH
	openAt time.Time
	_refs  *int32
}

func LocalOnly() *SSH {
	var refs int32
	return &SSH{
		localFs:     FsLocal{},
		remoteFs:    FsLocal{},
		sessionPool: newSessionPool(0),
		openAt:      time.Now(),
		_refs:       &refs,
	}
}

func NewSSH(client *ssh.Client, maxSession int, gate *SSH) (*SSH, error) {
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return nil, err
	}

	var refs int32
	return &SSH{
		conn:        client,
		sftp:        sftpClient,
		sessionPool: newSessionPool(maxSession),

		remoteFs: NewFsSftp(sftpClient),
		localFs:  FsLocal{},

		gate:   gate,
		openAt: time.Now(),
		_refs:  &refs,
	}, nil
}

// Dial create a SSH instance, only first gate was used if it exist and isn't nil
func Dial(addr string, auth *Auth, gate ...*SSH) (*SSH, error) {
	if len(gate) > 0 && gate[0] != nil {
		return gate[0].Dial(addr, auth)
	}
	config, err := auth.SSHConfig()
	if err != nil {
		return nil, err
	}

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, err
	}

	s, err := NewSSH(client, auth.MaxSession, nil)
	if err != nil {
		client.Close()
		return nil, err
	}
	return s, nil
}

func (s *SSH) DialConn(net, addr string) (net.Conn, error) {
	return s.conn.Dial(net, addr)
}

func (s *SSH) Dial(addr string, auth *Auth) (*SSH, error) {
	conn, err := s.conn.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	config, err := auth.SSHConfig()
	if err != nil {
		return nil, err
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		conn.Close()
		return nil, err
	}

	client := ssh.NewClient(c, chans, reqs)
	ssh, err := NewSSH(client, auth.MaxSession, s.NopClose())
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

func (s *SSH) clean() {
	s.err = nil
	s.cmdOutput = nil
}

// Closed should be called only if reference count is zero or it's Cloned by NopClose
func (s *SSH) Close() {
	s.clean()
	if s.nopClose {
		s.decrRefs()
		return
	}
	if s.gate != nil {
		s.gate.decrRefs()
	}
	if s.sessionPool != nil {
		s.sessionPool.Close()
	}
	if s.sftp != nil {
		s.sftp.Close()
	}
	if s.conn != nil {
		s.conn.Close()
	}
}

func (s *SSH) CmdOutput() []byte {
	if s.cmdOutput != nil {
		return s.cmdOutput.Bytes()
	}
	return nil
}

func (s *SSH) cmdOutToBuffer(out []byte, err error) ([]byte, error) {
	if s.cmdOutput != nil {
		s.cmdOutput.Write(out)
	}
	return out, err
}

func (s *SSH) ReserveCmdOutput(buf *bytes.Buffer) *SSH {
	if buf == nil {
		s.cmdOutput = bytes.NewBuffer(make([]byte, 0, 1024))
	} else {
		s.cmdOutput = buf
	}
	return s
}

func (s *SSH) checkError() error {
	if s.err != nil {
		return *s.err
	}
	return nil
}

func (s *SSH) saveError(err error) error {
	if err != nil && s.err != nil {
		*s.err = err
	}
	return err
}

func (s *SSH) ReserveError(e *error) *SSH {
	var err error
	if e == nil {
		e = &err
	}

	s.err = e
	return s
}

func (s *SSH) Error() error {
	if s.err == nil {
		return nil
	}
	return *s.err
}

func (s *SSH) ClearError() {
	if s.err != nil {
		*s.err = nil
	}
}

// NopClose create a clone of current SSH instance and increase the reference count.
// The Close method of returned instance will do nothing but decrease parent reference count.
func (s *SSH) NopClose() *SSH {
	s.incrRefs()
	if s.nopClose {
		return s
	}
	ns := *s

	ns.clean()
	ns.nopClose = true

	return &ns
}

func (s *SSH) LocalFs() Fs {
	return s.localFs
}

func (s *SSH) RemoteFs() Fs {
	return s.remoteFs
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
	err := s.checkError()
	if err != nil {
		return nil, s.saveError(err)
	}

	for {
		session, ok := s.sessionPool.Take()
		if !ok {
			return nil, ErrConnClosed
		}

		sess, err := s.conn.NewSession()
		if err != nil {
			if chanErr, ok := err.(*ssh.OpenChannelError); ok {
				if chanErr.Reason == ssh.Prohibited {
					session.Drop()
					continue
				}
			}

			session.Release()
			return nil, s.saveError(err)
		}

		defer func() {
			sess.Close()
			session.Release()
		}()

		out, err := s.cmdOutToBuffer(sess.CombinedOutput(s.rcmd(cmd, strings.Join(env, " "))))
		return out, s.saveError(err)
	}
}

func (s *SSH) cmdBg(cmd, stdout, stderr string) string {
	if stdout == "" {
		stdout = "nohup.out"
	}
	if stderr == "" || stderr == stdout {
		stderr = "&1"
	}
	return fmt.Sprintf("nohup %s >%s 2>%s </dev/null &", cmd, stdout, stderr)
}

func (s *SSH) Lcmd(cmd string, env ...string) ([]byte, error) {
	err := s.checkError()
	if err != nil {
		return nil, s.saveError(err)
	}

	c := exec.Command("sh", "-c", s.lcmd(cmd, strings.Join(env, " ")))
	if len(env) > 0 {
		c.Env = append(c.Env, env...)
	}
	out, err := s.cmdOutToBuffer(c.CombinedOutput())
	return out, s.saveError(err)
}

func (s *SSH) RcmdBg(cmd, stdout, stderr string, env ...string) ([]byte, error) {
	return s.Rcmd(s.cmdBg(cmd, stdout, stderr), env...)
}

func (s *SSH) LcmdBg(cmd, stdout, stderr string, env ...string) ([]byte, error) {
	return s.Lcmd(s.cmdBg(cmd, stdout, stderr), env...)
}

func (s *SSH) sync(fs, remoteFs Fs, path, remotePath string) error {
	err := s.checkError()
	if err != nil {
		return err
	}

	fd, err := fs.Open(path)
	if err != nil {
		return s.saveError(err)
	}
	defer fd.Close()

	info, err := fs.Stat(path)
	if err != nil {
		return s.saveError(err)
	}
	if !info.IsDir() {
		return s.saveError(s.syncFile(remoteFs, remotePath, fd, info))
	}

	dirnames, err := fd.Readdir(-1)
	if err != nil {
		return s.saveError(err)
	}

	lfpath, rfpath := fs.Filepath(), remoteFs.Filepath()
	for _, dirname := range dirnames {
		name := dirname.Name()
		err = s.sync(fs, remoteFs, lfpath.Join(path, name), rfpath.Join(remotePath, name))
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

	rfpath := rfs.Filepath()
	dir, _ := rfpath.Split(rpath)
	dir = rfpath.FromSlash(dir)

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

	bufsize := stat.Size()
	if bufsize > CopyBufferSize {
		bufsize = CopyBufferSize
	}
	if bufsize == 0 {
		bufsize = 1
	}
	_, err = io.CopyBuffer(rfd, fd, make([]byte, bufsize))
	if err == io.EOF {
		err = nil
	}
	return err
}

func (s *SSH) writeFile(fs Fs, path string, data []byte) error {
	err := s.checkError()
	if err != nil {
		return err
	}

	fd, err := s.openFile(fs, path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return s.saveError(err)
	}
	defer fd.Close()
	_, err = fd.Write(data)
	return s.saveError(err)
}

func (s *SSH) readFile(fs Fs, path string) ([]byte, error) {
	err := s.checkError()
	if err != nil {
		return nil, err
	}

	fd, err := s.openFile(fs, path, os.O_RDONLY, 0644)
	if err != nil {
		return nil, s.saveError(err)
	}
	defer fd.Close()

	data, err := ioutil.ReadAll(fd)
	return data, s.saveError(err)
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
	err := s.checkError()
	if err != nil {
		return nil, s.saveError(err)
	}

	f, err := fs.Open(path)
	if err != nil {
		return nil, s.saveError(err)
	}
	list, err := f.Readdir(n)
	f.Close()
	if err != nil {
		return nil, s.saveError(err)
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

func (s *SSH) remove(fs Fs, path string, recursive bool) error {
	err := s.checkError()
	if err != nil {
		return s.saveError(err)
	}

	if recursive {
		return s.saveError(fs.RemoveAll(path))
	}
	return s.saveError(fs.Remove(path))
}

func (s *SSH) Rremove(path string, recursive bool) error {
	return s.remove(s.remoteFs, s.rpath(path), recursive)
}

func (s *SSH) Lremove(path string, recursive bool) error {
	return s.remove(s.localFs, s.lpath(path), recursive)
}

func (s *SSH) exists(fs Fs, path string) (bool, error) {
	err := s.checkError()
	if err != nil {
		return false, err
	}

	_, err = fs.Stat(path)
	if err != nil {
		if fs.IsNotExist(err) {
			err = nil
		}
		return false, s.saveError(err)
	}
	return true, nil
}

func (s *SSH) Rexists(path string) (bool, error) {
	return s.exists(s.remoteFs, s.rpath(path))
}

func (s *SSH) Lexists(path string) (bool, error) {
	return s.exists(s.localFs, s.lpath(path))
}

func (s *SSH) rcmd(cmd, env string) string {
	return s.cmd(s.rcwd, env, cmd)
}

func (s *SSH) lcmd(cmd, env string) string {
	return s.cmd(s.lcwd, env, cmd)
}

func (s *SSH) cmd(cwd, env, cmd string) string {
	if env != "" {
		env = "export " + env + " " + CmdSeperator
	}
	if cwd != "" {
		cwd = "cd " + cwd + " " + CmdSeperator
	}
	return cwd + " " + env + " " + cmd
}

// Rcd will change the base path of relative path applied to remote host
func (s *SSH) Rcd(cwd string) {
	s.rcwd = s.rpath(cwd)
}

// TmpRcd will create an copy of current instance but doesn't change reference count,
// then call Rcd on it. It should only used for temporary change directory and be
// quickly destroyed.
func (s *SSH) TmpRcd(cwd string) *SSH {
	ns := *s
	ns.Rcd(cwd)
	return &ns
}

// Lcd do the same thing as Rcd but for local host
func (s *SSH) Lcd(cwd string) {
	s.lcwd = s.lpath(cwd)
}

// TmpLcd do the same thing as TmpLcd but for local host
func (s *SSH) TmpLcd(cwd string) *SSH {
	ns := *s
	ns.Lcd(cwd)
	return &ns
}

func (s *SSH) rpath(path string) string {
	return s.path(s.remoteFs.Filepath(), s.rcwd, path)
}

func (s *SSH) lpath(path string) string {
	return s.path(s.localFs.Filepath(), s.lcwd, path)
}

func (s *SSH) path(fpath Filepath, base, cwd string) string {
	if fpath.IsAbs(cwd) {
		return cwd
	}
	return fpath.Join(base, cwd)
}
