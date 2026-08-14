package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/Aakarsh133/ebpf-packetwall/pkg/extractor"
	"github.com/Aakarsh133/ebpf-packetwall/pkg/fetcher"

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

	var isRunning bool
	log.Println("Streaming...")

	fetcher := fetcher.New(url)
	executeCycle(&isRunning, fetcher)

	for range ticker.C {
		executeCycle(&isRunning, fetcher)
	}

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
