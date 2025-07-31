//go:build linux
// +build linux

package sniffer

import "time"

// getProcNameFallback provides Linux-specific port-based fallback
func (s *StatsManager) getProcNameFallback(localSocket LocalSocket) string {
	if s.stat.SocketFetcher == nil {
		return ""
	}

	if fetcher, ok := s.stat.SocketFetcher.(*netlinkConn); ok && fetcher != nil {
		fetcher.cacheMutex.RLock()
		defer fetcher.cacheMutex.RUnlock()

		if cached, found := fetcher.portCache[localSocket.Port]; found {
			if time.Since(cached.timestamp) < 5*time.Second {
				return cached.info.String()
			}
		}
	}

	return ""
}
