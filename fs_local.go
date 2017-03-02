package socker

import (
	"os"
	"time"
)

// FsLocal is the wrapper for package os
type FsLocal struct {
	localFilepath
}

var fsLocal Fs = FsLocal{}

func (f FsLocal) Filepath() Filepath {
	return f
}

func (FsLocal) Chmod(name string, mode os.FileMode) error {
	return os.Chmod(name, mode)
}

func (FsLocal) Chown(name string, uid, gid int) error {
	return os.Chown(name, uid, gid)
}

func (FsLocal) Chtimes(name string, atime time.Time, mtime time.Time) error {
	return os.Chtimes(name, atime, mtime)
}

func (FsLocal) Getwd() (dir string, err error) {
	return os.Getwd()
}

func (FsLocal) IsExist(err error) bool {
	return os.IsExist(err)
}

func (FsLocal) IsNotExist(err error) bool {
	return os.IsNotExist(err)
}

func (FsLocal) IsPermission(err error) bool {
	return os.IsPermission(err)
}

func (FsLocal) Mkdir(name string, perm os.FileMode) error {
	return os.Mkdir(name, perm)
}

func (FsLocal) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

func (FsLocal) Readlink(name string) (string, error) {
	return os.Readlink(name)
}

func (FsLocal) Remove(name string) error {
	return os.Remove(name)
}

func (FsLocal) RemoveAll(path string) error {
	return os.RemoveAll(path)
}

func (FsLocal) Rename(oldpath, newpath string) error {
	return os.Rename(oldpath, newpath)
}

func (FsLocal) SameFile(fi1, fi2 os.FileInfo) bool {
	return os.SameFile(fi1, fi2)
}

func (FsLocal) Symlink(oldname, newname string) error {
	return os.Symlink(oldname, newname)
}

func (FsLocal) Truncate(name string, size int64) error {
	return os.Truncate(name, size)
}

func (FsLocal) Create(name string) (File, error) {
	fd, err := os.Create(name)
	return fd, err
}

func (FsLocal) Open(name string) (File, error) {
	fd, err := os.Open(name)
	return fd, err
}

func (FsLocal) OpenFile(name string, flag int, perm os.FileMode) (File, error) {
	fd, err := os.OpenFile(name, flag, perm)
	return fd, err
}

func (FsLocal) Lstat(name string) (os.FileInfo, error) {
	return os.Lstat(name)
}

func (FsLocal) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}

func (FsLocal) Close() error {
	return nil
}
