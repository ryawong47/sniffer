//go:build linux
// +build linux

package sniffer

import (
	"fmt"
	"os"
	"time"

	"github.com/gizak/termui/v3"
)

type Sniffer struct {
	Opts           Options
	DnsResolver    *DNSResolver
	PcapClient     *PcapClient
	StatsManager   *StatsManager
	Ui             *UIComponent
	ProcessMonitor *ProcessMonitor
}

func NewSniffer(opts Options) (*Sniffer, error) {
	dnsResolver := NewDnsResolver()
	
	// Create and start process monitor
	processMonitor := NewProcessMonitor(2 * time.Second)
	if err := processMonitor.Start(); err != nil {
		return nil, fmt.Errorf("failed to start process monitor: %w", err)
	}
	
	pcapClient, err := NewPcapClient(dnsResolver.Lookup, opts, processMonitor)
	if err != nil {
		processMonitor.Stop()
		return nil, err
	}

	return &Sniffer{
		Opts:           opts,
		DnsResolver:    dnsResolver,
		PcapClient:     pcapClient,
		StatsManager:   NewStatsManager(opts),
		Ui:             NewUIComponent(opts),
		ProcessMonitor: processMonitor,
	}, nil
}

func (s *Sniffer) SwitchViewMode() {
	s.Opts.ViewMode = (s.Opts.ViewMode + 1) % 3
	s.StatsManager = NewStatsManager(s.Opts)

	s.Ui.Close()
	s.Ui = NewUIComponent(s.Opts)
}

func (s *Sniffer) Start() {
	events := termui.PollEvents()
	s.Refresh()
	var paused bool

	ticker := time.NewTicker(time.Duration(s.Opts.Interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case e := <-events:
			switch e.ID {
			case "<Tab>":
				s.Ui.viewer.Shift()
			case "<Space>":
				paused = !paused
			case "<Resize>":
				payload := e.Payload.(termui.Resize)
				s.Ui.viewer.Resize(payload.Width, payload.Height)
			case "s", "S":
				s.SwitchViewMode()
			case "q", "Q", "<C-c>":
				return
			}

		case <-ticker.C:
			if !paused {
				s.Refresh()
			}
		}
	}
}

func (s *Sniffer) Close() {
	s.Ui.Close()
	s.PcapClient.Close()
	s.DnsResolver.Close()
	s.ProcessMonitor.Stop()
}

func (s *Sniffer) Refresh() {
	utilization := s.PcapClient.Sinker.GetUtilization()
	
	// For Linux, we don't need OpenSockets anymore since process info
	// is already attached to ConnectionInfo
	s.StatsManager.Put(Stat{OpenSockets: make(OpenSockets), Utilization: utilization})
	s.Ui.viewer.Render(s.StatsManager.GetStats())
}

func exit(s string) {
	fmt.Fprintln(os.Stderr, "Start sniffer failed:", s)
	os.Exit(1)
}