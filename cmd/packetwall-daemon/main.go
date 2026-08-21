package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Aakarsh133/ebpf-packetwall/bpf"
	"github.com/Aakarsh133/ebpf-packetwall/pkg/extractor"
	"github.com/Aakarsh133/ebpf-packetwall/pkg/fetcher"
	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/joho/godotenv"
)

type ipv4LpmKey struct {
	prefixlen uint32
	addr      uint32
}

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatalf("Cannot load the env file")
	}

	authKey := os.Getenv("URLHAUS_AUTH")
	const urlhausAPI = "https://urlhaus-api.abuse.ch/v2/files/exports/%s/online.csv"
	url := fmt.Sprintf(urlhausAPI, authKey)

	ticker := time.NewTicker(time.Minute * 5)
	defer ticker.Stop()

	objs := bpf.BpfObjects{}

	if err := bpf.LoadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	ifacename := "lo"
	iface, err := net.InterfaceByName(ifacename)
	if err != nil {
		log.Fatalf("Cannot load interface: %s", err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpParseFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Cannot link with XDP: %s", err)
	}
	defer xdpLink.Close()
	log.Printf("ebpf-packetwall initiated..")

	var isRunning bool
	log.Println("Streaming...")

	fetcher := fetcher.New(url)

	go func() {
		executeCycle(&isRunning, fetcher, objs)

		for range ticker.C {
			executeCycle(&isRunning, fetcher, objs)
		}
	}()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper

	log.Printf("Exiting ebpf-packetwall.")

}

func executeCycle(isRunning *bool, f *fetcher.Fetcher, objs bpf.BpfObjects) {
	if *isRunning {
		log.Printf("Executing previous stream.. Wait for 5 minutes")
		return
	}

	*isRunning = true
	defer func() { *isRunning = false }()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*4+time.Second*30)
	defer cancel()

	stream, err := f.Fetch(ctx)
	if err != nil {
		log.Printf("Error: %s", err)
		return
	}

	defer stream.Close()
	ip4S, ip6S := extractor.ParseStream(stream)

	log.Printf("Completed Fetching->, IPV4 Records: %d, IPV6 Records: %d", len(ip4S), len(ip6S))

	keys := make([]ipv4LpmKey, len(ip4S))
	for i, ip := range ip4S {
		keys[i] = ipv4LpmKey{
			prefixlen: 32,
			addr:      ip,
		}
	}
	value := make([]uint32, len(ip4S))
	for i := range ip4S {
		value[i] = 1
	}

	_, err = objs.Ipv4LpmMap.BatchUpdate(keys, value, &ebpf.BatchOptions{ElemFlags: unix.BPF_ANY})
	if err != nil {
		log.Fatalf("batch update IPv4 LPM map: %v", err)
	}
}
