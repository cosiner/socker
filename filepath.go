// Package socker
package socker

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type Filepath interface {
	Separator() uint8
	ListSeparator() uint8
	IsPathSeparator(c uint8) bool
	Clean(path string) string
	ToSlash(path string) string
	FromSlash(path string) string
	SplitList(path string) []string
	Split(path string) (dir, file string)
	Join(elem ...string) string
	Ext(path string) string
	Abs(path string) (string, error)
	Rel(basepath, targpath string) (string, error)
	Base(path string) string
	Dir(path string) string
	VolumeName(path string) string
	IsAbs(path string) bool
}

type localFilepath struct {
}

var _ Filepath = localFilepath{}

func (localFilepath) Separator() uint8                     { return filepath.Separator }
func (localFilepath) ListSeparator() uint8                 { return filepath.ListSeparator }
func (localFilepath) IsPathSeparator(c uint8) bool         { return os.IsPathSeparator(c) }
func (localFilepath) Clean(path string) string             { return filepath.Clean(path) }
func (localFilepath) ToSlash(path string) string           { return filepath.ToSlash(path) }
func (localFilepath) FromSlash(path string) string         { return filepath.FromSlash(path) }
func (localFilepath) SplitList(path string) []string       { return filepath.SplitList(path) }
func (localFilepath) Split(path string) (dir, file string) { return filepath.Split(path) }
func (localFilepath) Join(elem ...string) string           { return filepath.Join(elem...) }
func (localFilepath) Ext(path string) string               { return filepath.Ext(path) }
func (localFilepath) Abs(path string) (string, error)      { return filepath.Abs(path) }
func (localFilepath) Rel(basepath, targpath string) (string, error) {
	return filepath.Rel(basepath, targpath)
}
func (localFilepath) Base(path string) string       { return filepath.Base(path) }
func (localFilepath) Dir(path string) string        { return filepath.Dir(path) }
func (localFilepath) VolumeName(path string) string { return filepath.VolumeName(path) }
func (localFilepath) IsAbs(path string) bool        { return filepath.IsAbs(path) }

type virtualFilepath struct {
	IsUnix            bool
	PathSeparator     uint8
	PathListSeparator uint8
	Getwd             func() (string, error)
}

var _ Filepath = virtualFilepath{}

func (f virtualFilepath) Separator() uint8 { return f.PathSeparator }

func (f virtualFilepath) ListSeparator() uint8 { return f.PathListSeparator }

func (f virtualFilepath) IsPathSeparator(c uint8) bool {
	return f.PathSeparator == c
}

func (f virtualFilepath) Clean(path string) string {
	return f.clean(path)
}

func (f virtualFilepath) ToSlash(path string) string {
	if f.PathSeparator == '/' {
		return path
	}
	return strings.Replace(path, string(f.PathSeparator), "/", -1)
}

func (f virtualFilepath) FromSlash(path string) string {
	if f.PathSeparator == '/' {
		return path
	}
	return strings.Replace(path, "/", string(f.PathSeparator), -1)
}

func (f virtualFilepath) SplitList(path string) []string {
	if f.IsUnix {
		return f.unixSplitList(path)
	}
	return f.windowsSplitList(path)
}

func (f virtualFilepath) Split(path string) (dir, file string) {
	vol := f.VolumeName(path)
	i := len(path) - 1
	for i >= len(vol) && !f.IsPathSeparator(path[i]) {
		i--
	}
	return path[:i+1], path[i+1:]
}

func (f virtualFilepath) Join(elem ...string) string {
	if f.IsUnix {
		return f.unixJoin(elem)
	}
	return f.windowsJoin(elem)
}

func (f virtualFilepath) Ext(path string) string {
	for i := len(path) - 1; i >= 0 && !f.IsPathSeparator(path[i]); i-- {
		if path[i] == '.' {
			return path[i:]
		}
	}
	return ""
}
func (f virtualFilepath) Abs(path string) (string, error) {
	if f.IsUnix {
		return f.unixAbs(path)
	}
	return f.windowsAbs(path)
}

func (f virtualFilepath) Rel(basepath, targpath string) (string, error) {
	baseVol := f.VolumeName(basepath)
	targVol := f.VolumeName(targpath)
	base := f.Clean(basepath)
	targ := f.Clean(targpath)
	if f.sameWord(targ, base) {
		return ".", nil
	}
	base = base[len(baseVol):]
	targ = targ[len(targVol):]
	if base == "." {
		base = ""
	}
	// Can't use IsAbs - `\a` and `a` are both relative in Windows.
	baseSlashed := len(base) > 0 && base[0] == f.PathSeparator
	targSlashed := len(targ) > 0 && targ[0] == f.PathSeparator
	if baseSlashed != targSlashed || !f.sameWord(baseVol, targVol) {
		return "", errors.New("Rel: can't make " + targpath + " relative to " + basepath)
	}
	// Position base[b0:bi] and targ[t0:ti] at the first differing elements.
	bl := len(base)
	tl := len(targ)
	var b0, bi, t0, ti int
	for {
		for bi < bl && base[bi] != f.PathSeparator {
			bi++
		}
		for ti < tl && targ[ti] != f.PathSeparator {
			ti++
		}
		if !f.sameWord(targ[t0:ti], base[b0:bi]) {
			break
		}
		if bi < bl {
			bi++
		}
		if ti < tl {
			ti++
		}
		b0 = bi
		t0 = ti
	}
	if base[b0:bi] == ".." {
		return "", errors.New("Rel: can't make " + targpath + " relative to " + basepath)
	}
	if b0 != bl {
		// Base elements left. Must go up before going down.
		seps := strings.Count(base[b0:bl], string(f.PathSeparator))
		size := 2 + seps*3
		if tl != t0 {
			size += 1 + tl - t0
		}
		buf := make([]byte, size)
		n := copy(buf, "..")
		for i := 0; i < seps; i++ {
			buf[n] = f.PathSeparator
			copy(buf[n+1:], "..")
			n += 3
		}
		if t0 != tl {
			buf[n] = f.PathSeparator
			copy(buf[n+1:], targ[t0:])
		}
		return string(buf), nil
	}
	return targ[t0:], nil
}

func (f virtualFilepath) Base(path string) string {
	if path == "" {
		return "."
	}
	// Strip trailing slashes.
	for len(path) > 0 && f.IsPathSeparator(path[len(path)-1]) {
		path = path[0 : len(path)-1]
	}
	// Throw away volume name
	path = path[len(f.VolumeName(path)):]
	// Find the last element
	i := len(path) - 1
	for i >= 0 && !f.IsPathSeparator(path[i]) {
		i--
	}
	if i >= 0 {
		path = path[i+1:]
	}
	// If empty now, it had only slashes.
	if path == "" {
		return string(f.PathSeparator)
	}
	return path
}

func (f virtualFilepath) Dir(path string) string {
	vol := f.VolumeName(path)
	i := len(path) - 1
	for i >= len(vol) && !f.IsPathSeparator(path[i]) {
		i--
	}
	dir := f.Clean(path[len(vol) : i+1])
	return vol + dir
}

func (f virtualFilepath) VolumeName(path string) string {
	return path[:f.volumeNameLen(path)]
}

func (f virtualFilepath) IsAbs(path string) bool {
	if f.IsUnix {
		return f.unixIsAbs(path)
	}
	return f.windowsIsAbs(path)
}

type lazybuf struct {
	path       string
	buf        []byte
	w          int
	volAndPath string
	volLen     int
}

func (b *lazybuf) index(i int) byte {
	if b.buf != nil {
		return b.buf[i]
	}
	return b.path[i]
}

func (b *lazybuf) append(c byte) {
	if b.buf == nil {
		if b.w < len(b.path) && b.path[b.w] == c {
			b.w++
			return
		}
		b.buf = make([]byte, len(b.path))
		copy(b.buf, b.path[:b.w])
	}
	b.buf[b.w] = c
	b.w++
}

func (b *lazybuf) string() string {
	if b.buf == nil {
		return b.volAndPath[:b.volLen+b.w]
	}
	return b.volAndPath[:b.volLen] + string(b.buf[:b.w])
}

func (f virtualFilepath) clean(path string) string {
	originalPath := path
	volLen := f.volumeNameLen(path)
	path = path[volLen:]
	if path == "" {
		if volLen > 1 && originalPath[1] != ':' {
			// should be UNC
			return f.FromSlash(originalPath)
		}
		return originalPath + "."
	}
	rooted := f.IsPathSeparator(path[0])

	// Invariants:
	//	reading from path; r is index of next byte to process.
	//	writing to buf; w is index of next byte to write.
	//	dotdot is index in buf where .. must stop, either because
	//		it is the leading slash or it is a leading ../../.. prefix.
	n := len(path)
	out := lazybuf{path: path, volAndPath: originalPath, volLen: volLen}
	r, dotdot := 0, 0
	if rooted {
		out.append(f.PathSeparator)
		r, dotdot = 1, 1
	}

	for r < n {
		switch {
		case f.IsPathSeparator(path[r]):
			// empty path element
			r++
		case path[r] == '.' && (r+1 == n || f.IsPathSeparator(path[r+1])):
			// . element
			r++
		case path[r] == '.' && path[r+1] == '.' && (r+2 == n || f.IsPathSeparator(path[r+2])):
			// .. element: remove to last separator
			r += 2
			switch {
			case out.w > dotdot:
				// can backtrack
				out.w--
				for out.w > dotdot && !f.IsPathSeparator(out.index(out.w)) {
					out.w--
				}
			case !rooted:
				// cannot backtrack, but not rooted, so append .. element.
				if out.w > 0 {
					out.append(f.PathSeparator)
				}
				out.append('.')
				out.append('.')
				dotdot = out.w
			}
		default:
			// real path element.
			// add slash if needed
			if rooted && out.w != 1 || !rooted && out.w != 0 {
				out.append(f.PathSeparator)
			}
			// copy element
			for ; r < n && !f.IsPathSeparator(path[r]); r++ {
				out.append(path[r])
			}
		}
	}

	// Turn empty string into "."
	if out.w == 0 {
		out.append('.')
	}

	return f.FromSlash(out.string())
}

func (f virtualFilepath) unixSplitList(path string) []string {
	if path == "" {
		return []string{}
	}
	return strings.Split(path, string(f.PathListSeparator))
}

func (f virtualFilepath) windowsSplitList(path string) []string {
	// The same implementation is used in LookPath in os/exec;
	// consider changing os/exec when changing this.

	if path == "" {
		return []string{}
	}

	// Split path, respecting but preserving quotes.
	list := []string{}
	start := 0
	quo := false
	for i := 0; i < len(path); i++ {
		switch c := path[i]; {
		case c == '"':
			quo = !quo
		case c == f.PathListSeparator && !quo:
			list = append(list, path[start:i])
			start = i + 1
		}
	}
	list = append(list, path[start:])

	// Remove quotes.
	for i, s := range list {
		if strings.Contains(s, `"`) {
			list[i] = strings.Replace(s, `"`, ``, -1)
		}
	}

	return list
}

func (f virtualFilepath) volumeNameLen(path string) int {
	if f.IsUnix {
		return f.unixVolumeNameLen(path)
	}
	return f.windowsVolumeNameLen(path)
}

func (f virtualFilepath) unixVolumeNameLen(path string) int {
	return 0
}

func (f virtualFilepath) windowsVolumeNameLen(path string) int {
	if len(path) < 2 {
		return 0
	}
	// with drive letter
	c := path[0]
	if path[1] == ':' && ('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z') {
		return 2
	}
	// is it UNC? https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247(v=vs.85).aspx
	if l := len(path); l >= 5 && f.windowsIsSlash(path[0]) && f.windowsIsSlash(path[1]) &&
		!f.windowsIsSlash(path[2]) && path[2] != '.' {
		// first, leading `\\` and next shouldn't be `\`. its server name.
		for n := 3; n < l-1; n++ {
			// second, next '\' shouldn't be repeated.
			if f.windowsIsSlash(path[n]) {
				n++
				// third, following something characters. its share name.
				if !f.windowsIsSlash(path[n]) {
					if path[n] == '.' {
						break
					}
					for ; n < l; n++ {
						if f.windowsIsSlash(path[n]) {
							break
						}
					}
					return n
				}
				break
			}
		}
	}
	return 0
}

func (f virtualFilepath) windowsIsSlash(c uint8) bool {
	return c == '\\' || c == '/'
}

func (f virtualFilepath) isAbs(path string) bool {
	if f.IsUnix {
		return f.unixIsAbs(path)
	}
	return f.windowsIsAbs(path)
}

func (f virtualFilepath) unixIsAbs(path string) bool {
	return strings.HasPrefix(path, "/")
}

// IsAbs reports whether the path is absolute.
func (f virtualFilepath) windowsIsAbs(path string) (b bool) {
	l := f.windowsVolumeNameLen(path)
	if l == 0 {
		return false
	}
	path = path[l:]
	if path == "" {
		return false
	}
	return f.windowsIsSlash(path[0])
}

func (f virtualFilepath) abs(path string) (string, error) {
	if f.IsUnix {
		return f.unixAbs(path)
	}
	return f.windowsAbs(path)
}

func (f virtualFilepath) unixAbs(path string) (string, error) {
	if f.unixIsAbs(path) {
		return f.clean(path), nil
	}

	wd, err := f.Getwd()
	if err != nil {
		return "", err
	}
	return f.unixJoin([]string{wd, path}), nil
}

func (f virtualFilepath) windowsAbs(path string) (string, error) {
	// need windows syscall
	return path, nil
}

func (f virtualFilepath) join(elem []string) string {
	if f.IsUnix {
		return f.unixJoin(elem)
	}
	return f.windowsJoin(elem)
}

func (f virtualFilepath) unixJoin(elem []string) string {
	for i, e := range elem {
		if e != "" {
			return f.clean(strings.Join(elem[i:], string(f.PathSeparator)))
		}
	}
	return ""
}

func (f virtualFilepath) windowsJoin(elem []string) string {
	for i, e := range elem {
		if e != "" {
			return f.windowsJoinNonEmpty(elem[i:])
		}
	}
	return ""
}

// joinNonEmpty is like join, but it assumes that the first element is non-empty.
func (f virtualFilepath) windowsJoinNonEmpty(elem []string) string {
	if len(elem[0]) == 2 && elem[0][1] == ':' {
		// First element is drive letter without terminating slash.
		// Keep path relative to current directory on that drive.
		return f.clean(elem[0] + strings.Join(elem[1:], string(f.PathSeparator)))
	}
	// The following logic prevents Join from inadvertently creating a
	// UNC path on Windows. Unless the first element is a UNC path, Join
	// shouldn't create a UNC path. See golang.org/issue/9167.
	p := f.clean(strings.Join(elem, string(f.PathSeparator)))
	if !f.windowsIsUNC(p) {
		return p
	}
	// p == UNC only allowed when the first element is a UNC path.
	head := f.clean(elem[0])
	if f.windowsIsUNC(head) {
		return p
	}
	// head + tail == UNC, but joining two non-UNC paths should not result
	// in a UNC path. Undo creation of UNC path.
	tail := f.clean(strings.Join(elem[1:], string(f.PathSeparator)))
	if head[len(head)-1] == f.PathSeparator {
		return head + tail
	}
	return head + string(f.PathSeparator) + tail
}

func (f virtualFilepath) windowsIsUNC(path string) bool {
	return f.windowsVolumeNameLen(path) > 2
}

func (f virtualFilepath) sameWord(a, b string) bool {
	if f.IsUnix {
		return f.unixSameWord(a, b)
	}
	return f.windowsSameWord(a, b)
}

func (f virtualFilepath) windowsSameWord(a, b string) bool {
	return strings.EqualFold(a, b)
}

func (f virtualFilepath) unixSameWord(a, b string) bool {
	return a == b
}
