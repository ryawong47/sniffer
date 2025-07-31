package main

import (
	"fmt"
	"log"
	"strings"
	"time"

	sniffer "."
)

func main() {
	// Configure options
	opt := sniffer.Options{
		Interval:          1, // 1 second interval
		ViewMode:          sniffer.ModeTableBytes,
		DeviceNames:       []string{}, // Empty means all devices
		DisableDNSResolve: false,
		AllDevices:        true,
	}

	// Initialize components
	dnsResolver := sniffer.NewDnsResolver()
	pcapClient, err := sniffer.NewPcapClient(dnsResolver.Lookup, opt)
	if err != nil {
		log.Fatalf("Failed to create pcap client: %v", err)
	}
	defer pcapClient.Close()

	socketFetcher := sniffer.GetSocketFetcher()
	statsmanager := sniffer.NewStatsManager(opt)

	fmt.Println("Starting network sniffer...")
	fmt.Println("Press Ctrl+C to stop")
	fmt.Println("---")

	// Main monitoring loop
	for {
		utilization := pcapClient.Sinker.GetUtilization()
		openSockets, err := socketFetcher.GetOpenSockets()
		if err != nil {
			log.Printf("Error getting open sockets: %v", err)
			time.Sleep(time.Duration(opt.Interval) * time.Second)
			continue
		}

		statsmanager.Put(sniffer.Stat{
			OpenSockets:   openSockets,
			Utilization:   utilization,
			SocketFetcher: socketFetcher,
		})

		snapshot := statsmanager.GetStats().(*sniffer.Snapshot)

		// Print statistics
		fmt.Printf("\n=== Network Statistics (Time: %s) ===\n", time.Now().Format("15:04:05"))

		fmt.Printf("\nTotal Connections: %d\n", snapshot.TotalConnections)
		fmt.Printf("Total Upload: %d bytes\n", snapshot.TotalUploadBytes)
		fmt.Printf("Total Download: %d bytes\n", snapshot.TotalDownloadBytes)

		fmt.Printf("\nTop Processes:\n")
		for i, proc := range snapshot.TopNProcesses(5, sniffer.ModeTableBytes) {
			fmt.Printf("  %d. %s - Upload: %d bytes, Download: %d bytes, Connections: %d\n",
				i+1, proc.ProcessName, proc.Data.UploadBytes, proc.Data.DownloadBytes, proc.Data.ConnCount)
		}

		fmt.Printf("\nTop Remote Addresses:\n")
		for i, addr := range snapshot.TopNRemoteAddrs(5, sniffer.ModeTableBytes) {
			fmt.Printf("  %d. %s - Upload: %d bytes, Download: %d bytes, Connections: %d\n",
				i+1, addr.Addr, addr.Data.UploadBytes, addr.Data.DownloadBytes, addr.Data.ConnCount)
		}

		fmt.Printf("\nTop Connections:\n")
		for i, conn := range snapshot.TopNConnections(5, sniffer.ModeTableBytes) {
			fmt.Printf("  %d. %s:%d -> %s:%d (%s) - Process: %s, Upload: %d bytes, Download: %d bytes\n",
				i+1,
				conn.Conn.Local.IP, conn.Conn.Local.Port,
				conn.Conn.Remote.IP, conn.Conn.Remote.Port,
				conn.Conn.Local.Protocol,
				conn.Data.ProcessName,
				conn.Data.UploadBytes, conn.Data.DownloadBytes)
		}

		fmt.Println("\n" + strings.Repeat("-", 80))

		time.Sleep(time.Duration(opt.Interval) * time.Second)
	}
}
