//go:build !linux
// +build !linux

package sniffer

import (
	"fmt"
	"os"
	"time"

	"github.com/gizak/termui/v3"
)

func exit(s string) {
	fmt.Fprintln(os.Stderr, "Start sniffer failed:", s)
	os.Exit(1)
}

// Options is the options set for the sniffer instance.
type Options struct {
	// BPFFilter is the string pcap filter with the BPF syntax
	// eg. "tcp and port 80"
	BPFFilter string

	// Interval is the interval for refresh rate in seconds
	Interval int

	// ViewMode represents the sniffer view mode, optional: bytes, packets, processes
	ViewMode ViewMode

	// DevicesPrefix represents prefixed devices to monitor
	DevicesPrefix []string

	// Unit of stats in processes mode, optional: B, Kb, KB, Mb, MB, Gb, GB
	Unit Unit

	// DisableDNSResolve decides whether if disable the DNS resolution
	DisableDNSResolve bool

	// AllDevices specifies whether to listen all devices or not
	AllDevices bool
}

func (o Options) Validate() error {
	if err := o.ViewMode.Validate(); err != nil {
		return err
	}
	if err := o.Unit.Validate(); err != nil {
		return err
	}
	return nil
}

func DefaultOptions() Options {
	return Options{
		BPFFilter:         "tcp or udp",
		Interval:          2,
		ViewMode:          ModeTableBytes,
		Unit:              UnitKB,
		DevicesPrefix:     []string{"en", "lo", "eth", "em", "bond"},
		DisableDNSResolve: false,
		AllDevices:        false,
	}
}

type Sniffer struct {
	Opts          Options
	DnsResolver   *DNSResolver
	PcapClient    *PcapClient
	StatsManager  *StatsManager
	Ui            *UIComponent
	SocketFetcher SocketFetcher
}

func NewSniffer(opts Options) (*Sniffer, error) {
	dnsResolver := NewDnsResolver()
	pcapClient, err := NewPcapClient(dnsResolver.Lookup, opts, nil)
	if err != nil {
		return nil, err
	}

	return &Sniffer{
		Opts:          opts,
		DnsResolver:   dnsResolver,
		PcapClient:    pcapClient,
		StatsManager:  NewStatsManager(opts),
		Ui:            NewUIComponent(opts),
		SocketFetcher: GetSocketFetcher(),
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
}

func (s *Sniffer) Refresh() {
	utilization := s.PcapClient.Sinker.GetUtilization()
	openSockets, err := s.SocketFetcher.GetOpenSockets()
	if err != nil {
		return
	}

	s.StatsManager.Put(Stat{OpenSockets: openSockets, Utilization: utilization})
	s.Ui.viewer.Render(s.StatsManager.GetStats())
}
