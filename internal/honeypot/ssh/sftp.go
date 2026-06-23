package ssh

import (
	"bytes"
	"io"
	"os"
	"path"
	"time"

	"github.com/pkg/sftp"

	"github.com/c2xorc4/mimic/internal/events"
)

// serveSFTP handles an "sftp" subsystem request by serving the honeypot's
// in-memory Linux VFS over the SFTP protocol — read-only (downloads + listings),
// rejecting writes/renames/deletes like a locked-down service account. Crucially
// it is backed by the vnode tree, NOT the real host filesystem (pkg/sftp's
// NewServer would expose the real disk).
func (s *Server) serveSFTP(ch io.ReadWriteCloser, remote string) {
	h := &sftpHandler{s: s, remote: remote}
	handlers := sftp.Handlers{FileGet: h, FilePut: h, FileCmd: h, FileList: h}
	rs := sftp.NewRequestServer(ch, handlers)
	defer rs.Close()
	s.emit(remote, events.Event{Type: events.Connection, Severity: events.SevWarn, Message: "SFTP subsystem opened"})
	_ = rs.Serve() // returns on client EOF
}

// sftpHandler implements pkg/sftp's FileReader/FileWriter/FileCmder/FileLister
// against the honeypot VFS.
type sftpHandler struct {
	s      *Server
	remote string
}

// Fileread serves a download from the VFS.
func (h *sftpHandler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	n := h.s.vfs().resolve(path.Clean(r.Filepath))
	if n == nil {
		return nil, os.ErrNotExist
	}
	if n.dir {
		return nil, os.ErrInvalid
	}
	h.s.emit(h.remote, events.Event{Type: events.FileDownload, Severity: events.SevWarn, Message: "SFTP file download",
		Fields: map[string]interface{}{"path": path.Clean(r.Filepath), "bytes": len(n.content)}})
	return bytes.NewReader(n.content), nil
}

// Filewrite rejects uploads (read-only honeypot account).
func (h *sftpHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	h.s.emit(h.remote, events.Event{Type: events.Enumeration, Severity: events.SevWarn, Message: "SFTP upload attempt (denied)",
		Fields: map[string]interface{}{"path": path.Clean(r.Filepath)}})
	return nil, os.ErrPermission
}

// Filecmd rejects mutating ops (mkdir/rename/remove/setstat/...).
func (h *sftpHandler) Filecmd(r *sftp.Request) error {
	h.s.emit(h.remote, events.Event{Type: events.Enumeration, Severity: events.SevNotice, Message: "SFTP " + r.Method + " (denied)",
		Fields: map[string]interface{}{"path": path.Clean(r.Filepath)}})
	return os.ErrPermission
}

// Filelist serves List (directory contents), Stat, and Readlink.
func (h *sftpHandler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	abs := path.Clean(r.Filepath)
	n := h.s.vfs().resolve(abs)
	if n == nil {
		return nil, os.ErrNotExist
	}
	switch r.Method {
	case "List":
		if !n.dir {
			return nil, os.ErrInvalid
		}
		h.s.emit(h.remote, events.Event{Type: events.Enumeration, Severity: events.SevNotice, Message: "SFTP directory listing",
			Fields: map[string]interface{}{"path": abs}})
		var fis []os.FileInfo
		for _, name := range n.childNames() {
			fis = append(fis, &vnodeFileInfo{n.children[name]})
		}
		return listerAt(fis), nil
	case "Stat", "Lstat", "Readlink":
		return listerAt{&vnodeFileInfo{n}}, nil
	default:
		return nil, os.ErrInvalid
	}
}

// listerAt adapts a slice of FileInfo to sftp.ListerAt.
type listerAt []os.FileInfo

func (l listerAt) ListAt(f []os.FileInfo, off int64) (int, error) {
	if off >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(f, l[off:])
	if int(off)+n >= len(l) {
		return n, io.EOF
	}
	return n, nil
}

// vnodeFileInfo adapts a vnode to os.FileInfo for SFTP responses.
type vnodeFileInfo struct{ n *vnode }

func (f *vnodeFileInfo) Name() string       { return f.n.name }
func (f *vnodeFileInfo) Size() int64        { return f.n.size() }
func (f *vnodeFileInfo) ModTime() time.Time { return f.n.mtime }
func (f *vnodeFileInfo) IsDir() bool        { return f.n.dir }
func (f *vnodeFileInfo) Sys() interface{}   { return nil }
func (f *vnodeFileInfo) Mode() os.FileMode {
	if f.n.dir {
		return os.ModeDir | 0o755
	}
	return 0o644
}
