package main

import (
	"context"
	"ebpf-packetwall/pkg/fetcher"
	"log"
	"time"
)

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

}
