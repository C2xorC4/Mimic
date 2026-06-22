package smb

// BaitUser is a fake local account surfaced by SAMR/LSA enumeration. RID is the
// account's relative identifier (combined with the domain SID for a full SID, so
// SAMR EnumUsers and LSA SID/name lookups stay self-consistent).
type BaitUser struct {
	RID  uint32
	Name string
}

// PipeRPCEnv carries host identity into named-pipe DCE/RPC handlers.
type PipeRPCEnv struct {
	ComputerName string
	DomainName   string
	// Users are the bait accounts SAMR enumeration returns (Windows built-ins +
	// seeded credentials). Surfaced only to authenticated sessions.
	Users []BaitUser
	// Authenticated is true when the SMB session bound with a real credential
	// (not guest/null). Modern Windows denies anonymous SAM enumeration
	// (RestrictAnonymousSAM=1), so SAMR EnumUsers gates on this.
	Authenticated bool
}

// PipeContext is the request-scoped input for pipe Read/Write/Transceive.
type PipeContext struct {
	Shares []ShareInfo
	Env    PipeRPCEnv
}