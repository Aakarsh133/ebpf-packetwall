package extractor

import (
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"

	"github.com/praserx/ipconv"
)

func parseIp(rawUrl string) ([]net.IP, error) {
	parsed, err := url.Parse(rawUrl)
	if err != nil {
		return nil, fmt.Errorf("Cannot parse URL")
	}

	host := parsed.Hostname()
	if host == "" {
		return nil, fmt.Errorf("Cannot resolve host")
	}

	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("Cannot resolve DNS")
	}

	return ips, nil

}

func ParseStream(stream io.ReadCloser) (ipS []uint32, ip6S [][16]byte) {
	var ip4s []uint32
	var ip6s [][16]byte
	reader := csv.NewReader(stream)
	reader.Comment = '#'
	const targetCol = 2

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		if len(record) > targetCol {
			rawUrl := record[2]
			ip, err := parseIp(rawUrl)

			if err != nil {
				log.Printf("Cannot parse IP: %s", err)
				continue
			}

			for _, singleIP := range ip {
				if ipv4 := singleIP.To4(); ipv4 != nil {
					ipInt, err := ipconv.IPv4ToInt(ipv4)
					if err != nil {
						log.Printf("Cannot parse to byte stream: %s", err)
						continue
					}
					ip4s = append(ip4s, ipInt)
				} else if ipv6 := singleIP.To16(); ipv6 != nil {
					var v6Arr [16]byte
					copy(v6Arr[:], ipv6)
					ip6s = append(ip6s, v6Arr)
				}
			}

		}
	}
	return ip4s, ip6s
}
