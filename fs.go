package socker

import (
	"io"
	"os"
	"time"
)

// Fs is the abstract interface for local and sftp filesystem
type Fs interface {
	Filepath() Filepath

	Chmod(name string, mode os.FileMode) error
	Chown(name string, uid, gid int) error
	Chtimes(name string, atime time.Time, mtime time.Time) error

	Getwd() (dir string, err error)
	IsExist(err error) bool
	IsNotExist(err error) bool

	IsPermission(err error) bool
	Mkdir(name string, perm os.FileMode) error
	MkdirAll(path string, perm os.FileMode) error
	Readlink(name string) (string, error)
	Remove(name string) error
	RemoveAll(path string) error
	Rename(oldpath, newpath string) error
	SameFile(fi1, fi2 os.FileInfo) bool
	Symlink(oldname, newname string) error
	Truncate(name string, size int64) error

	Create(name string) (File, error)
	Open(name string) (File, error)
	OpenFile(name string, flag int, perm os.FileMode) (File, error)

	Lstat(name string) (os.FileInfo, error)
	Stat(name string) (os.FileInfo, error)

	io.Closer
}

// File is the abstract interface for local and sftp file
type File interface {
	io.Closer
	Chmod(mode os.FileMode) error
	Chown(uid, gid int) error
	Name() string
	Read(b []byte) (n int, err error)
	Readdir(n int) ([]os.FileInfo, error)
	Readdirnames(n int) (names []string, err error)
	Seek(offset int64, whence int) (ret int64, err error)
	Stat() (os.FileInfo, error)
	Truncate(size int64) error
	Write(b []byte) (n int, err error)
	WriteString(s string) (n int, err error)
}
