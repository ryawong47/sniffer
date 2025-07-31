package main

import (
	"fmt"
	"log"
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

	dnsResolver := sniffer.NewDnsResolver()
	pcapClient, err := sniffer.NewPcapClient(dnsResolver.Lookup, opt)
	socketFetcher := sniffer.GetSocketFetcher()
	statsmanager := sniffer.NewStatsManager(opt)

	if err != nil {
		log.Fatalf("Failed to create pcap client: %v", err)
		return
	}

	for {
		utilization := pcapClient.Sinker.GetUtilization()
		openSockets, err := socketFetcher.GetOpenSockets()
		if err != nil {
			log.Printf("Error getting open sockets: %v", err)
			return
		}

		statsmanager.Put(sniffer.Stat{OpenSockets: openSockets, Utilization: utilization, SocketFetcher: socketFetcher})

		snapshot := statsmanager.GetStats().(*sniffer.Snapshot)

		fmt.Println("Connections: ", snapshot.Connections)
		fmt.Println("Processes: ", snapshot.Processes)
		fmt.Println("RemoteAddrs: ", snapshot.RemoteAddrs)
		fmt.Println("TotalConnections: ", snapshot.TotalConnections)
		fmt.Println("topN connections: ", snapshot.TopNConnections(10, sniffer.ModeTableBytes))
		time.Sleep(time.Duration(opt.Interval) * time.Second)
	}
}
