package extractor

import (
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"sync"

	"github.com/praserx/ipconv"
)

func parseHosts(rawUrl string, hosts chan string) error {
	parsed, err := url.Parse(rawUrl)
	if err != nil {
		return fmt.Errorf("Cannot parse URL")
	}

	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("Cannot resolve host")
	}

	hosts <- host
	return nil

}

func parseIp(hosts chan string, ips chan net.IP) {
	for host := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			ips <- ip
		}
		ip6, err := net.LookupIP(host)
		if err != nil {
			log.Printf("Cannot resolve DNS: %s", host)
		}
		for _, ip := range ip6 {
			ips <- ip
		}
	}
}

func ParseStream(stream io.ReadCloser) (ipS []uint32, ip6S [][16]byte) {
	var ip4s []uint32
	var ip6s [][16]byte
	reader := csv.NewReader(stream)
	reader.Comment = '#'
	const targetCol = 2

	hosts := make(chan string)
	ips := make(chan net.IP)

	wg1 := sync.WaitGroup{}
	wg2 := sync.WaitGroup{}

	wg2.Go(func() {
		for ip := range ips {
			if ipv4 := ip.To4(); ipv4 != nil {
				ipInt, err := ipconv.IPv4ToInt(ipv4)
				if err != nil {
					log.Printf("Cannot parse to byte stream: %s", err)
					continue
				}
				ip4s = append(ip4s, ipInt)
			} else if ipv6 := ip.To16(); ipv6 != nil {
				var v6Arr [16]byte
				copy(v6Arr[:], ipv6)
				ip6s = append(ip6s, v6Arr)
			}
		}
	})

	for range 50 {
		wg1.Go(func() {
			parseIp(hosts, ips)
		})
	}

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		if len(record) > targetCol {
			rawUrl := record[targetCol]
			err := parseHosts(rawUrl, hosts)

			if err != nil {
				log.Printf("Cannot parse IP: %s", err)
				continue
			}
		}
	}

	close(hosts)
	wg1.Wait()
	close(ips)
	wg2.Wait()

	return ip4s, ip6s
}
