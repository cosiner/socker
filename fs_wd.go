package socker

import (
	"os"
	"time"
)

func fsPath(fs Fs, wd, path string) string {
	if fs.Filepath().IsAbs(path) {
		return path
	}
	return fs.Filepath().Join(wd, path)
}

type wdFs struct {
	wd string

	fs Fs
}

func newWdFs(prefix string, fs Fs) Fs {
	if prefix == "" {
		return fs
	}

	return wdFs{wd: prefix, fs: fs}
}

func (f wdFs) Filepath() Filepath {
	return f.fs.Filepath()
}

func (f wdFs) path(name string) string {
	return fsPath(f.fs, f.wd, name)
}
func (f wdFs) Chmod(name string, mode os.FileMode) error {
	return f.fs.Chmod(f.path(name), mode)
}

func (f wdFs) Chown(name string, uid, gid int) error {
	return f.fs.Chown(f.path(name), uid, gid)
}

func (f wdFs) Chtimes(name string, atime time.Time, mtime time.Time) error {
	return f.fs.Chtimes(f.path(name), atime, mtime)
}

func (f wdFs) IsExist(err error) bool {
	return f.fs.IsExist(err)
}

func (f wdFs) IsNotExist(err error) bool {
	return f.fs.IsNotExist(err)
}

func (f wdFs) IsPermission(err error) bool {
	return f.fs.IsPermission(err)
}

func (f wdFs) Mkdir(name string, perm os.FileMode) error {
	return f.fs.Mkdir(f.path(name), perm)
}

func (f wdFs) MkdirAll(path string, perm os.FileMode) error {
	return f.fs.MkdirAll(f.path(path), perm)
}

func (f wdFs) Readlink(name string) (string, error) {
	return f.fs.Readlink(f.path(name))
}

func (f wdFs) Remove(name string) error {
	return f.fs.Remove(f.path(name))
}

func (f wdFs) RemoveAll(path string) error {
	return f.fs.RemoveAll(f.path(path))
}

func (f wdFs) Rename(oldpath, newpath string) error {
	return f.fs.Rename(f.path(oldpath), f.path(newpath))
}

func (f wdFs) SameFile(fi1, fi2 os.FileInfo) bool {
	return f.fs.SameFile(fi1, fi2)
}

func (f wdFs) Symlink(oldname, newname string) error {
	return f.fs.Symlink(f.path(oldname), f.path(newname))
}

func (f wdFs) Truncate(name string, size int64) error {
	return f.fs.Truncate(f.path(name), size)
}

func (f wdFs) Create(name string) (File, error) {
	return f.fs.Create(f.path(name))
}

func (f wdFs) Open(name string) (File, error) {
	return f.fs.Open(f.path(name))
}

func (f wdFs) OpenFile(name string, flag int, perm os.FileMode) (File, error) {
	return f.fs.OpenFile(f.path(name), flag, perm)
}

func (f wdFs) Lstat(name string) (os.FileInfo, error) {
	return f.fs.Lstat(f.path(name))
}

func (f wdFs) Stat(name string) (os.FileInfo, error) {
	return f.fs.Stat(f.path(name))
}

func (f wdFs) Close() error {
	return f.fs.Close()
}
