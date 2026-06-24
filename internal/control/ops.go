package control

// NormalizeOp maps legacy or alias operation names to their canonical form.
// Service lifecycle ops use the services.* prefix to match services.list.
func NormalizeOp(op string) string {
	switch op {
	case "service.restart":
		return "services.restart"
	case "service.stop":
		return "services.stop"
	case "service.start":
		return "services.start"
	default:
		return op
	}
}