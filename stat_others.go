//go:build !linux
// +build !linux

package sniffer

// getProcNameFallback provides a no-op fallback for non-Linux platforms
func (s *StatsManager) getProcNameFallback(localSocket LocalSocket) string {
	return ""
}
