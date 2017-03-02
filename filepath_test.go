package socker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFilepath(t *testing.T) {
	var lfpath Filepath = localFilepath{}
	var vfpath Filepath = virtualFilepath{
		PathSeparator:     filepath.Separator,
		PathListSeparator: filepath.ListSeparator,
		IsUnix:            filepath.Separator == '/',
		Getwd:             os.Getwd,
	}

	if lfpath.Join("a", "b", "c") != vfpath.Join("a", "b", "c") {
		t.Error("test join failed")
	}
	if lfpath.IsAbs("a") != vfpath.IsAbs("a") {
		t.Error("test abs failed")
	}
	if lfpath.Dir(".") != vfpath.Dir(".") {
		t.Error("test dir failed")
	}
	if lfpath.VolumeName("c:\\aaa") != vfpath.VolumeName("c:\\aaa") {
		t.Error("test volumeName failed")
	}
}
