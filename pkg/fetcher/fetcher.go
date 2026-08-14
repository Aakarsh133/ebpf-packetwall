package fetcher

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

type Fetcher struct {
	client *http.Client
	url    string
}

func New(apiURL string) *Fetcher {
	return &Fetcher{
		client: &http.Client{},
		url:    apiURL,
	}
}

func (f *Fetcher) Fetch(ctx context.Context) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot build request: %w", err)
	}
	req.Header.Set("User-Agent", "ebpf-packetwall")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot fetch responses: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("Unexpected status code %d", resp.StatusCode)
	}

	return resp.Body, nil

}
