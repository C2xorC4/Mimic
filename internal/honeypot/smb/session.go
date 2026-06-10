package smb

import "sync"

// handle map lives on Session; keyed by volatile FileId (uint64).

// SessionState is the per-connection SMB2 protocol state.
type SessionState int

const (
	StateNew           SessionState = iota // TCP connected, no SMB exchange yet
	StateNegotiated                        // NEGOTIATE complete
	StateSetupPending                      // SESSION_SETUP round 1 sent (challenge issued)
	StateAuthenticated                     // SESSION_SETUP round 2 accepted
)

// Session tracks the SMB2 state for a single TCP connection.
// One connection = one session (multi-session per connection is not emulated).
type Session struct {
	id        uint64 // assigned on SESSION_SETUP round 1
	remote    string // client remote address (host:port), for event attribution
	state     SessionState
	dialect   uint16                 // negotiated SMBv2 dialect (set during NEGOTIATE)
	challenge [8]byte                // server challenge sent in round 1
	trees     map[uint32]string      // SMBv2 treeID → UNC path
	nextTree  uint32                 // monotonically incrementing tree ID counter
	handles   map[uint64]*FileHandle // volatile FileId → open handle

	// SMBv1 state (TID=uint16, FID=uint16 by protocol spec)
	smb1Trees   map[uint16]string
	smb1Handles map[uint16]*PipeState
	smb1NextTID uint16
	smb1NextFID uint16

	mu sync.Mutex
}

func newSession() *Session {
	return &Session{
		trees:       make(map[uint32]string),
		handles:     make(map[uint64]*FileHandle),
		smb1Trees:   make(map[uint16]string),
		smb1Handles: make(map[uint16]*PipeState),
		state:       StateNew,
	}
}

func (s *Session) setState(st SessionState) {
	s.mu.Lock()
	s.state = st
	s.mu.Unlock()
}

func (s *Session) getState() SessionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

func (s *Session) setChallenge(c [8]byte) {
	s.mu.Lock()
	s.challenge = c
	s.mu.Unlock()
}

func (s *Session) getChallenge() [8]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.challenge
}

// allocTree registers a new tree connection and returns the assigned tree ID.
func (s *Session) allocTree(uncPath string) uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextTree++
	id := s.nextTree
	s.trees[id] = uncPath
	return id
}

// freeTree removes a tree connection.
func (s *Session) freeTree(treeID uint32) {
	s.mu.Lock()
	delete(s.trees, treeID)
	s.mu.Unlock()
}

// treePath returns the UNC path for a tree ID, or "" if not connected.
func (s *Session) treePathFor(treeID uint32) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.trees[treeID]
}

// allocHandle registers a new open handle and returns its volatile FileId.
func (s *Session) allocHandle(node *VFSNode, shareName string) uint64 {
	id := nextHandleID()
	h := &FileHandle{node: node, shareName: shareName}
	s.mu.Lock()
	s.handles[id] = h
	s.mu.Unlock()
	return id
}

// allocPipeHandle registers a named-pipe handle and returns its volatile FileId.
func (s *Session) allocPipeHandle(pipe *PipeState) uint64 {
	id := nextHandleID()
	h := &FileHandle{pipe: pipe}
	s.mu.Lock()
	s.handles[id] = h
	s.mu.Unlock()
	return id
}

// getHandle retrieves an open handle by volatile FileId; returns nil if unknown.
func (s *Session) getHandle(volatileID uint64) *FileHandle {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.handles[volatileID]
}

// freeHandle removes an open handle.
func (s *Session) freeHandle(volatileID uint64) {
	s.mu.Lock()
	delete(s.handles, volatileID)
	s.mu.Unlock()
}

// resetDir resets directory enumeration state for a handle (SL_RESTART_SCAN).
// The mazeChildren cache is cleared so the listing is regenerated on the next call.
func (s *Session) resetDir(volatileID uint64) {
	s.mu.Lock()
	if h := s.handles[volatileID]; h != nil {
		h.dirIdx = 0
		h.mazeChildren = nil
	}
	s.mu.Unlock()
}
