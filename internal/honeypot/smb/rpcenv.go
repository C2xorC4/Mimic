package smb

// PipeRPCEnv carries host identity strings into named-pipe DCE/RPC handlers.
type PipeRPCEnv struct {
	ComputerName string
	DomainName   string
}

// PipeContext is the request-scoped input for pipe Read/Write/Transceive.
type PipeContext struct {
	Shares []ShareInfo
	Env    PipeRPCEnv
}