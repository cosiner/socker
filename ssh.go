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

var ErrConnClosed = errors.New("connection closed")

type SSH struct {
	lastErr    error
	lastOutput []byte
	rIn        io.Reader
	rOut, rErr io.Writer
	lIn        io.Reader
	lOut, lErr io.Writer

	nopClose bool

	conn        *ssh.Client
	sftp        *sftp.Client
	sessionPool *sessionPool

	// absolute fs
	rfs Fs
	lfs Fs

	// current work dir
	rwd string
	cwd string

	gate   *SSH
	openAt time.Time
	_refs  *int32
}

func LocalOnly() *SSH {
	var refs int32
	return &SSH{
		lfs:         FsLocal{},
		rfs:         FsLocal{},
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
	s := &SSH{
		conn:        client,
		sftp:        sftpClient,
		sessionPool: newSessionPool(maxSession),

		rfs: NewFsSftp(sftpClient),
		lfs: FsLocal{},

		gate:   gate,
		openAt: time.Now(),
		_refs:  &refs,
	}
	if err == nil {
		s.cwd, err = os.Getwd()
		if err == nil && !s.lfs.Filepath().IsAbs(s.cwd) {
			err = fmt.Errorf("local work dir is not absolute: %s", s.cwd)
		}
	}
	if err == nil {
		s.rwd, err = sftpClient.Getwd()
		if err == nil && !s.rfs.Filepath().IsAbs(s.rwd) {
			err = fmt.Errorf("remote work dir is not absolute: %s", s.rwd)
		}
	}
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("get remote/local working directory failed: %w", err)
	}
	return s, nil
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
	s.lastErr = nil
	s.lastOutput = nil
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

func (s *SSH) RemotePipeInput(stdin io.Reader) {
	s.rIn = stdin
}

func (s *SSH) LocalPipeInput(stdin io.Reader) {
	s.lIn = stdin
}

func (s *SSH) RemotePipeOutput(stdout, stderr io.Writer) {
	s.rOut = stdout
	s.rErr = stderr
}

func (s *SSH) LocalPipeOutput(stdout, stderr io.Writer) {
	s.lOut = stdout
	s.lErr = stderr
}

func (s *SSH) withErrorCheck(fn func() error) {
	if s.lastErr == nil {
		s.lastErr = fn()
	}
}

func (s *SSH) Error() error {
	return s.lastErr
}

// save error state from external, such as fs op
func (s *SSH) SetError(err error) {
	s.lastErr = s.lastErr
}

func (s *SSH) ClearError() {
	s.lastErr = nil
}

func (s *SSH) Output() []byte {
	return s.lastOutput
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

func (s *SSH) Lfs() Fs {
	return newWdFs(s.cwd, s.lfs)
}

func (s *SSH) Rfs() Fs {
	return newWdFs(s.rwd, s.rfs)
}

func (s *SSH) Rcmd(cmd string, env ...string) {
	s.withErrorCheck(func() error {
		return s.runRcmd(cmd, env...)
	})
}

func (s *SSH) Lcmd(cmd string, env ...string) {
	s.withErrorCheck(func() error {
		return s.runLcmd(cmd, env...)
	})
}

func (s *SSH) RcmdBg(cmd, stdout, stderr string, env ...string) {
	s.Rcmd(s.cmdStrBg(cmd, stdout, stderr), env...)
}

func (s *SSH) LcmdBg(cmd, stdout, stderr string, env ...string) {
	s.Lcmd(s.cmdStrBg(cmd, stdout, stderr), env...)
}

func (s *SSH) LwriteFile(path string, data []byte) {
	s.withErrorCheck(func() error {
		return s.writeFile(s.lfs, s.lpath(path), data)
	})
}

func (s *SSH) RwriteFile(path string, data []byte) {
	s.withErrorCheck(func() error {
		return s.writeFile(s.rfs, s.rpath(path), data)
	})
}

func (s *SSH) LreadFile(path string) []byte {
	var (
		data []byte
		err  error
	)
	s.withErrorCheck(func() error {
		data, err = s.readFile(s.lfs, s.lpath(path))
		return err
	})
	return data
}

func (s *SSH) RreadFile(path string) []byte {
	var (
		data []byte
		err  error
	)
	s.withErrorCheck(func() error {
		data, err = s.readFile(s.rfs, s.rpath(path))
		return err
	})
	return data
}

func (s *SSH) Lreaddir(path string, n int) []os.FileInfo {
	var (
		items []os.FileInfo
		err   error
	)
	s.withErrorCheck(func() error {
		items, err = s.readdir(s.lfs, s.lpath(path), n)
		return err
	})
	return items
}

func (s *SSH) Rreaddir(path string, n int) []os.FileInfo {
	var (
		items []os.FileInfo
		err   error
	)
	s.withErrorCheck(func() error {
		items, err = s.readdir(s.rfs, s.rpath(path), n)
		return err
	})
	return items
}

func (s *SSH) Put(path, remotePath string) {
	s.withErrorCheck(func() error {
		return s.sync(s.lfs, s.rfs, s.lpath(path), s.rpath(remotePath))
	})
}

func (s *SSH) Get(remotePath, path string) {
	s.withErrorCheck(func() error {
		return s.sync(s.rfs, s.lfs, s.rpath(remotePath), s.lpath(path))
	})
}

func (s *SSH) Rremove(path string, recursive bool) {
	s.withErrorCheck(func() error {
		return s.remove(s.rfs, s.rpath(path), recursive)
	})
}

func (s *SSH) Lremove(path string, recursive bool) {
	s.withErrorCheck(func() error {
		return s.remove(s.lfs, s.lpath(path), recursive)
	})
}

func (s *SSH) Rexists(path string) bool {
	var (
		exists bool
		err    error
	)
	s.withErrorCheck(func() error {
		exists, err = s.exists(s.rfs, s.rpath(path))
		return err
	})
	return exists
}

func (s *SSH) Lexists(path string) bool {
	var (
		exists bool
		err    error
	)
	s.withErrorCheck(func() error {
		exists, err = s.exists(s.lfs, s.lpath(path))
		return err
	})
	return exists
}

// Rcwd return current remote working directory
func (s *SSH) Rcwd() string {
	return s.rwd
}

// Rcd will change the base path of relative path applied to remote host
func (s *SSH) Rcd(cwd string) {
	s.rwd = s.rpath(cwd)
}

// TmpRcd will create an copy of current instance but doesn't change reference count,
// then call Rcd on it. It should only used for temporary change directory and be
// quickly destroyed.
func (s *SSH) TmpRcd(cwd string) *SSH {
	ns := *s
	ns.Rcd(cwd)
	return &ns
}

// Lcwd return current local working directory
func (s *SSH) Lcwd() string {
	return s.cwd
}

// Lcd do the same thing as Rcd but for local host
func (s *SSH) Lcd(cwd string) {
	s.cwd = s.lpath(cwd)
}

// TmpLcd do the same thing as TmpLcd but for local host
func (s *SSH) TmpLcd(cwd string) *SSH {
	ns := *s
	ns.Lcd(cwd)
	return &ns
}

// private

func (s *SSH) rcmdStr(cmd, env string) string {
	return s.cmdStr(s.rwd, env, cmd)
}

func (s *SSH) lcmdStr(cmd, env string) string {
	return s.cmdStr(s.cwd, env, cmd)
}

func (s *SSH) cmdStr(cwd, env, cmd string) string {
	if env != "" {
		env = "export " + env + " " + CmdSeperator
	}
	if cwd != "" {
		cwd = "cd " + cwd + " " + CmdSeperator
	}
	return cwd + " " + env + " " + cmd
}

func (s *SSH) remove(fs Fs, path string, recursive bool) error {
	if recursive {
		return fs.RemoveAll(path)
	}
	return fs.Remove(path)
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

func (s *SSH) runCmd(isRemote bool, stdin *io.Reader, stdout, stderr *io.Writer, run func() error) error {
	var (
		in     io.Reader
		ow, ew io.Writer
	)
	if isRemote {
		in = s.rIn
		ow, ew = s.rOut, s.rErr
	} else {
		in = s.lIn
		ow, ew = s.lOut, s.lErr
	}
	*stdin = in
	if ow == nil && ew == nil {
		var b bytes.Buffer
		*stdout = &b
		*stderr = &b
		err := run()
		s.lastOutput = b.Bytes()
		return err
	}

	*stdout = ow
	*stderr = ew
	s.lastOutput = nil
	return run()
}

func (s *SSH) runRcmd(cmd string, env ...string) error {
	for {
		session, ok := s.sessionPool.Take()
		if !ok {
			return ErrConnClosed
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
			return err
		}

		defer func() {
			sess.Close()
			session.Release()
		}()

		cmd := s.rcmdStr(cmd, strings.Join(env, " "))
		return s.runCmd(true, &sess.Stdin, &sess.Stdout, &sess.Stderr, func() error {
			return sess.Run(cmd)
		})
	}
}

func (s *SSH) cmdStrBg(cmd, stdout, stderr string) string {
	if stdout == "" {
		stdout = "nohup.out"
	}
	if stderr == "" || stderr == stdout {
		stderr = "&1"
	}
	return fmt.Sprintf("nohup %s >%s 2>%s </dev/null &", cmd, stdout, stderr)
}

func (s *SSH) runLcmd(cmd string, env ...string) error {
	c := exec.Command("sh", "-c", s.lcmdStr(cmd, strings.Join(env, " ")))
	if len(env) > 0 {
		c.Env = append(c.Env, env...)
	}
	return s.runCmd(false, &c.Stdin, &c.Stdout, &c.Stderr, func() error {
		return c.Run()
	})
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

func (s *SSH) rpath(path string) string {
	return fsPath(s.rfs, s.rwd, path)
}

func (s *SSH) lpath(path string) string {
	return fsPath(s.lfs, s.cwd, path)
}
