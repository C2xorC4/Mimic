package platform

import (
	"errors"
	"strings"
	"syscall"
)

// IsAddrInUse reports whether err is a listen/bind "address already in use" failure.
func IsAddrInUse(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "address already in use") ||
		strings.Contains(msg, "only one usage of each socket address")
}