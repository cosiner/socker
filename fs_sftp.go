package socker

import (
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/pkg/sftp"
)

type FsSftp struct {
	sftp  *sftp.Client
	fpath Filepath
}

func NewFsSftp(sftp *sftp.Client) Fs {
	fs := FsSftp{sftp: sftp}
	_, err := fs.Stat("/")

	var (
		separator     uint8
		listSeparator uint8
	)
	if err != nil && fs.IsNotExist(err) {
		// windows
		separator = '\\'
		listSeparator = ';'
	} else {
		// unix
		separator = '/'
		listSeparator = ':'
	}
	if separator == os.PathSeparator {
		fs.fpath = localFilepath{}
	} else {
		fs.fpath = virtualFilepath{
			PathSeparator:     separator,
			PathListSeparator: listSeparator,
			IsUnix:            separator == '/',
			Getwd:             sftp.Getwd,
		}
	}
	return fs
}

func (s FsSftp) Filepath() Filepath {
	return s.fpath
}

func (s FsSftp) Chmod(name string, mode os.FileMode) error {
	return s.sftp.Chmod(name, mode)
}

func (s FsSftp) Chown(name string, uid, gid int) error {
	return s.sftp.Chown(name, uid, gid)
}

func (s FsSftp) Chtimes(name string, atime time.Time, mtime time.Time) error {
	return s.sftp.Chtimes(name, atime, mtime)
}

func (s FsSftp) Getwd() (dir string, err error) {
	return s.sftp.Getwd()
}

func (s FsSftp) IsExist(err error) bool {
	const ssh_FX_FILE_ALREADY_EXISTS = 11
	se, ok := err.(*sftp.StatusError)
	if ok {
		return se.Code == ssh_FX_FILE_ALREADY_EXISTS
	}
	return strings.Contains(err.Error(), "already exist") || os.IsExist(err)
}

func (s FsSftp) IsNotExist(err error) bool {
	const ssh_FX_NO_SUCH_FILE = 2
	se, ok := err.(*sftp.StatusError)
	if ok {
		return ok && se.Code == ssh_FX_NO_SUCH_FILE
	}
	return strings.Contains(err.Error(), "not exist") || os.IsNotExist(err)
}

func (s FsSftp) IsPermission(err error) bool {
	return os.IsPermission(err)
}

func (s FsSftp) Mkdir(name string, perm os.FileMode) error {
	err := s.sftp.Mkdir(name)
	if err == nil {
		err = s.sftp.Chmod(name, perm)
	}
	return err
}

func (s FsSftp) MkdirAll(path string, perm os.FileMode) error {
	// Copy from os.MkdirAll
	dir, err := s.sftp.Stat(path)
	if err == nil {
		if dir.IsDir() {
			return nil
		}
		return &os.PathError{Op: "mkdir", Path: path, Err: syscall.ENOTDIR}
	}

	i := len(path)
	for i > 0 && s.fpath.IsPathSeparator(path[i-1]) { // Skip trailing path separator.
		i--
	}
	j := i
	for j > 0 && !s.fpath.IsPathSeparator(path[j-1]) { // Scan backward over element.
		j--
	}
	if j > 1 {
		err = s.MkdirAll(path[0:j-1], perm)
		if err != nil {
			return err
		}
	}
	err = s.Mkdir(path, perm)
	if err != nil {
		dir, err1 := s.Lstat(path)
		if err1 == nil && dir.IsDir() {
			return nil
		}
		return err
	}
	return nil
}

func (s FsSftp) Readlink(name string) (string, error) {
	return s.sftp.ReadLink(name)
}

func (s FsSftp) Remove(name string) error {
	return s.sftp.Remove(name)
}

func (s FsSftp) removeDir(path string) error {
	fd, err := s.Open(path)
	if err != nil {
		if s.IsNotExist(err) {
			return nil
		}
		return err
	}

	separator := s.fpath.Separator()
	err = nil
	for {
		names, err1 := fd.Readdirnames(100)
		for _, name := range names {
			err1 := s.RemoveAll(path + string(separator) + name)
			if err == nil {
				err = err1
			}
		}
		if err1 == io.EOF {
			break
		}
		if err == nil {
			err = err1
		}
		if len(names) == 0 {
			break
		}
	}
	fd.Close()

	err1 := s.Remove(path)
	if err1 == nil || s.IsNotExist(err1) {
		return nil
	}
	if err == nil {
		err = err1
	}
	return err
}

func (s FsSftp) RemoveAll(path string) error {
	// Copy from os.RemoveAll
	err := s.Remove(path)
	if err == nil || s.IsNotExist(err) {
		return nil
	}

	dir, serr := s.Lstat(path)
	if serr != nil {
		if serr, ok := serr.(*os.PathError); ok && (s.IsNotExist(serr.Err) || serr.Err == syscall.ENOTDIR) {
			return nil
		}
		return serr
	}
	if !dir.IsDir() {
		return err
	}

	return s.removeDir(path)
}

func (s FsSftp) Rename(oldpath, newpath string) error {
	return s.sftp.Rename(oldpath, newpath)
}

func (s FsSftp) SameFile(fi1, fi2 os.FileInfo) bool {
	return os.SameFile(fi1, fi2)
}

func (s FsSftp) Symlink(oldname, newname string) error {
	return s.sftp.Symlink(oldname, newname)
}

func (s FsSftp) Truncate(name string, size int64) error {
	return s.sftp.Truncate(name, size)
}

func (s FsSftp) Create(name string) (File, error) {
	return s.OpenFile(name, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
}

func (s FsSftp) Open(name string) (File, error) {
	fd, err := s.sftp.Open(name)

	return s.newFile(name, fd, err)
}

func (s FsSftp) OpenFile(name string, flag int, perm os.FileMode) (File, error) {
	var chmod bool
	if flag&os.O_CREATE != 0 {
		_, err := s.Stat(name)
		chmod = err != nil && s.IsNotExist(err)
	}

	fd, err := s.sftp.OpenFile(name, flag)
	if err != nil {
		return nil, err
	}

	if chmod {
		fd.Chmod(perm)
	}
	return s.newFile(name, fd, nil)
}

func (s FsSftp) Lstat(name string) (os.FileInfo, error) {
	return s.sftp.Lstat(name)
}

func (s FsSftp) Stat(name string) (os.FileInfo, error) {
	return s.sftp.Stat(name)
}

func (s FsSftp) newFile(path string, fd *sftp.File, err error) (File, error) {
	if err != nil {
		return nil, err
	}
	return &fileSftp{
		File: fd,
		path: path,
		sftp: s,
	}, nil
}

func (s FsSftp) Close() error {
	return s.sftp.Close()
}

type fileSftp struct {
	*sftp.File
	path string
	sftp FsSftp
}

func (f *fileSftp) Readdir(n int) ([]os.FileInfo, error) {
	fis, err := f.sftp.sftp.ReadDir(f.path)
	if err != nil {
		return nil, err
	}
	if n > 0 && len(fis) > n {
		fis = fis[:n]
	}
	return fis, nil
}

func (f *fileSftp) Readdirnames(n int) (names []string, err error) {
	fis, err := f.Readdir(n)
	if err != nil {
		return nil, err
	}
	names = make([]string, len(fis))
	for i := range fis {
		names[i] = fis[i].Name()
	}
	return names, nil
}

func (f *fileSftp) WriteString(s string) (n int, err error) {
	return f.File.Write([]byte(s))
}
