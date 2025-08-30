package sniffer

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