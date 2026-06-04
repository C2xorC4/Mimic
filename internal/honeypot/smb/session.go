package smb

import "sync"

// SessionState is the per-connection SMB2 protocol state.
type SessionState int

const (
	StateNew          SessionState = iota // TCP connected, no SMB exchange yet
	StateNegotiated                       // NEGOTIATE complete
	StateSetupPending                     // SESSION_SETUP round 1 sent (challenge issued)
	StateAuthenticated                    // SESSION_SETUP round 2 accepted
)

// Session tracks the SMB2 state for a single TCP connection.
// One connection = one session (multi-session per connection is not emulated).
type Session struct {
	id        uint64               // assigned on SESSION_SETUP round 1
	state     SessionState
	challenge [8]byte              // server challenge sent in round 1
	trees     map[uint32]string    // treeID → UNC path
	nextTree  uint32               // monotonically incrementing tree ID counter
	mu        sync.Mutex
}

func newSession() *Session {
	return &Session{
		trees: make(map[uint32]string),
		state: StateNew,
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
