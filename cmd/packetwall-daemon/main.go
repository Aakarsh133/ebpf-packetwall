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

	"github.com/cilium/ebpf/link"
	"github.com/joho/godotenv"
)

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
		executeCycle(&isRunning, fetcher)

		for range ticker.C {
			executeCycle(&isRunning, fetcher)
		}
	}()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	<-stopper

	log.Printf("Exiting ebpf-packetwall.")

}

func executeCycle(isRunning *bool, f *fetcher.Fetcher) {
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
	ipS, ip6S := extractor.ParseStream(stream)

	log.Printf("Completed, %d %d", len(ipS), len(ip6S))

}
