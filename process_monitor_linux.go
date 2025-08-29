//go:build linux
// +build linux

package sniffer

import (
	"context"
	"sync"
	"time"
)

// ProcessMonitor maintains a real-time map of sockets to processes
type ProcessMonitor struct {
	mu              sync.RWMutex
	socketMap       map[LocalSocket]ProcessInfo // socket -> process mapping
	refreshInterval time.Duration
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
	nlConn          *netlinkConn
}

// NewProcessMonitor creates a new process monitor
func NewProcessMonitor(refreshInterval time.Duration) *ProcessMonitor {
	ctx, cancel := context.WithCancel(context.Background())
	return &ProcessMonitor{
		socketMap:       make(map[LocalSocket]ProcessInfo),
		refreshInterval: refreshInterval,
		ctx:             ctx,
		cancel:          cancel,
		nlConn:          &netlinkConn{},
	}
}

// Start begins monitoring processes and their sockets
func (pm *ProcessMonitor) Start() error {
	// Initial refresh
	if err := pm.RefreshProcesses(); err != nil {
		return err
	}

	// Start background refresh goroutine
	pm.wg.Add(1)
	go func() {
		defer pm.wg.Done()
		ticker := time.NewTicker(pm.refreshInterval)
		defer ticker.Stop()

		for {
			select {
			case <-pm.ctx.Done():
				return
			case <-ticker.C:
				pm.RefreshProcesses()
			}
		}
	}()

	return nil
}

// Stop stops the process monitor
func (pm *ProcessMonitor) Stop() {
	pm.cancel()
	pm.wg.Wait()
}

// RefreshProcesses updates the socket-to-process mapping
func (pm *ProcessMonitor) RefreshProcesses() error {
	// Get all PIDs
	pids, err := pm.nlConn.listPids()
	if err != nil {
		return err
	}

	// Build inode to process map
	inodeMap := pm.nlConn.getAllProcsInodes(pids...)

	// Get all open sockets
	openSockets, err := pm.nlConn.getOpenSockets(inodeMap)
	if err != nil {
		return err
	}

	// Update the socket map
	pm.mu.Lock()
	pm.socketMap = openSockets
	pm.mu.Unlock()

	return nil
}

// GetProcess returns the process info for a given socket, or nil if unknown
func (pm *ProcessMonitor) GetProcess(socket LocalSocket) *ProcessInfo {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// Try exact match first
	if proc, ok := pm.socketMap[socket]; ok {
		return &proc
	}

	// Try with wildcard IP (for listening sockets)
	wildcardSocket := socket
	wildcardSocket.IP = "*"
	if proc, ok := pm.socketMap[wildcardSocket]; ok {
		return &proc
	}

	// Try with 0.0.0.0 (another form of wildcard)
	wildcardSocket.IP = "0.0.0.0"
	if proc, ok := pm.socketMap[wildcardSocket]; ok {
		return &proc
	}

	// Try with :: for IPv6
	wildcardSocket.IP = "::"
	if proc, ok := pm.socketMap[wildcardSocket]; ok {
		return &proc
	}

	return nil
}

// GetAllProcessSockets returns all current socket-to-process mappings
func (pm *ProcessMonitor) GetAllProcessSockets() map[LocalSocket]ProcessInfo {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// Return a copy to avoid race conditions
	result := make(map[LocalSocket]ProcessInfo)
	for k, v := range pm.socketMap {
		result[k] = v
	}
	return result
}