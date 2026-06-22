package smb

import (
	"crypto/sha512"
	"sync"
)

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

	// SMB 3.1.1 preauth-integrity running hash (nil until a 3.1.1 NEGOTIATE
	// initialises it) and the derived signing state. These are touched only from
	// the single per-connection handler goroutine, in protocol order, so they
	// need no locking.
	preauth       []byte // 64-byte running SHA-512 preauth hash
	signingKey    []byte // 16-byte SMB2 signing key (set on verified-cred auth)
	signingActive bool   // sign responses on this session
	guestSession  bool   // true for guest/null sessions (IS_GUEST / anonymous)
	seededAuth    bool   // verified config-seeded credential; maze/admin-share access

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

// preauthInit starts the SMB 3.1.1 preauth-integrity hash at the all-zero seed.
// Idempotent: a second NEGOTIATE on the same connection does not reset it.
func (s *Session) preauthInit() {
	if s.preauth == nil {
		s.preauth = make([]byte, 64)
	}
}

// preauthUpdate folds one SMB2 message (without the 4-byte transport header)
// into the running preauth hash: H = SHA512(H || msg). No-op until preauthInit
// has run, so non-3.1.1 sessions never accumulate a hash.
func (s *Session) preauthUpdate(msg []byte) {
	if s.preauth == nil {
		return
	}
	h := sha512.New()
	h.Write(s.preauth)
	h.Write(msg)
	s.preauth = h.Sum(nil)
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

func (s *Session) setGuest(guest bool) {
	s.mu.Lock()
	s.guestSession = guest
	s.mu.Unlock()
}

func (s *Session) isGuest() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.guestSession
}

func (s *Session) setSeededAuth(seeded bool) {
	s.mu.Lock()
	s.seededAuth = seeded
	s.mu.Unlock()
}

func (s *Session) isSeededAuth() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seededAuth
}

// canAccessAdminShare reports whether this session may tree-connect C$/ADMIN$.
// Guest/null sessions are blocked; verified seeded credentials are always allowed
// even when the SESSION_SETUP response carried IS_GUEST so the client skips signing.
func (s *Session) canAccessAdminShare() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seededAuth {
		return true
	}
	return !s.guestSession
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
