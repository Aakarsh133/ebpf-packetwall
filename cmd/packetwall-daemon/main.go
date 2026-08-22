package main

import (
	"context"
	"encoding/binary"
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
	Prefixlen uint32
	Addr      uint32
}
type ipv6LpmKey struct {
	Prefixlen uint32
	Addr      [4]uint32
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
		i := 1
		log.Printf("Initiating cycle %d", i)
		executeCycle(&isRunning, fetcher, &objs)
		log.Printf("Cycle %d completed", i)
		for range ticker.C {
			i++
			log.Printf("Initiating cycle %d", i)
			executeCycle(&isRunning, fetcher, &objs)
			log.Printf("Cycle %d completed", i)
		}
	}()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper

	log.Printf("Exiting ebpf-packetwall.")

}

func updateMaps(ip4S []uint32, ip6S [][16]byte, objs *bpf.BpfObjects) {
	log.Printf("Inserting Values in maps. ")
	keys := make([]ipv4LpmKey, len(ip4S))
	for i, ip := range ip4S {
		keys[i] = ipv4LpmKey{
			Prefixlen: 32,
			Addr:      ip,
		}
	}
	value := make([]uint32, len(ip4S))
	for i := range ip4S {
		value[i] = 1
	}

	_, err := objs.Ipv4LpmMap.BatchUpdate(keys, value, &ebpf.BatchOptions{ElemFlags: unix.BPF_ANY})
	if err != nil {
		log.Printf("batch update IPv4 LPM map: %v", err)
	}

	keysIp6 := make([]ipv6LpmKey, len(ip6S))
	value = make([]uint32, len(ip6S))
	for i := range ip6S {
		value[i] = 1
	}

	var KAddr [4]uint32

	for j, ip := range ip6S {
		KAddr[0] = binary.LittleEndian.Uint32(ip[0:4])
		KAddr[1] = binary.LittleEndian.Uint32(ip[4:8])
		KAddr[2] = binary.LittleEndian.Uint32(ip[8:12])
		KAddr[3] = binary.LittleEndian.Uint32(ip[12:16])
		keysIp6[j] = ipv6LpmKey{
			Prefixlen: 128,
			Addr:      KAddr,
		}
	}

	_, err = objs.Ipv6LpmMap.BatchUpdate(keysIp6, value, &ebpf.BatchOptions{ElemFlags: unix.BPF_ANY})
	if err != nil {
		log.Printf("batch update IPv6 LPM map: %v", err)
	}
	log.Printf("Values inserted in maps. ")

}

func executeCycle(isRunning *bool, f *fetcher.Fetcher, objs *bpf.BpfObjects) {
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

	updateMaps(ip4S, ip6S, objs)

}
