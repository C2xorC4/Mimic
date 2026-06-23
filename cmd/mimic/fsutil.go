package main

import (
	_ "embed"
	"io"
	"os"
)

// starterConfig is the example config written by `install` (both platforms) when
// no config exists yet. Operators edit it before starting the service.
//
//go:embed assets/config.starter.yaml
var starterConfig []byte

// copyFile copies src to dst with the given mode (atomic via temp + rename).
// Shared by the per-platform install commands.
func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}
