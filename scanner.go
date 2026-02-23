package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	workers    = 15
	ratePerSec = 20
	timeout    = 3 * time.Second
	retryDelay = 1500 * time.Millisecond
	retryMax   = 1
)

// Host header to send with every request.
// Change this to whatever domain your ISP zero-rates.
// e.g. "www.facebook.com", "wikipedia.org", "www.whatsapp.com"
const zeroRatedHost = "www.facebook.com"

var probePorts = []struct {
	port   string
	scheme string
}{
	{"80", "http"},
	{"8080", "http"},
	{"443", "https"},
}

func ipGenerator(cidr string) (<-chan string, int, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, 0, err
	}

	ones, bits := ipNet.Mask.Size()
	total := (1 << (bits - ones)) - 2
	if total < 0 {
		total = 0
	}

	ch := make(chan string, workers*2)

	go func() {
		defer close(ch)
		start := binary.BigEndian.Uint32(ipNet.IP.To4())
		mask := binary.BigEndian.Uint32(ipNet.Mask)
		end := (start & mask) | (^mask)

		for i := start + 1; i < end; i++ {
			ip := make(net.IP, 4)
			binary.BigEndian.PutUint32(ip, i)
			ch <- ip.String()
		}
	}()

	return ch, total, nil
}

type PortResult struct {
	port      string
	scheme    string
	status    int   // HTTP status code, 0 if no response
	bytesSent int64 // content-length from response header
	timedOut  bool
	responded bool
}

func probePort(ip, port, scheme string) PortResult {
	result := PortResult{port: port, scheme: scheme}

	// custom transport that connects to the raw IP but sends the Host header
	// this is what actually tests zero-rating — the ISP sees the Host header
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		// skip TLS verification since we're hitting an IP directly, not a domain
		TLSClientConfig: nil,
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects, log the raw response
		},
	}

	url := fmt.Sprintf("%s://%s:%s/", scheme, ip, port)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return result
	}

	// this is the key line — tells the ISP/CDN which domain we want
	req.Host = zeroRatedHost
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible)")

	resp, err := client.Do(req)
	if err != nil {
		e := err.Error()
		if strings.Contains(e, "timeout") || strings.Contains(e, "deadline") {
			result.timedOut = true
		}
		return result
	}
	defer resp.Body.Close()

	result.responded = true
	result.status = resp.StatusCode
	result.bytesSent = resp.ContentLength
	return result
}

type ScanResult struct {
	ip          string
	ports       []PortResult
	allTimedOut bool
}

func scanIP(ip string) ScanResult {
	for attempt := 0; attempt <= retryMax; attempt++ {
		if attempt > 0 {
			time.Sleep(retryDelay)
		}

		results := make([]PortResult, len(probePorts))
		var wg sync.WaitGroup

		for i, p := range probePorts {
			wg.Add(1)
			go func(idx int, port, scheme string) {
				defer wg.Done()
				results[idx] = probePort(ip, port, scheme)
			}(i, p.port, p.scheme)
		}
		wg.Wait()

		timeoutCount := 0
		respondedCount := 0
		for _, r := range results {
			if r.timedOut {
				timeoutCount++
			}
			if r.responded {
				respondedCount++
			}
		}

		allTimedOut := timeoutCount == len(probePorts)

		if !allTimedOut || attempt == retryMax {
			return ScanResult{
				ip:          ip,
				ports:       results,
				allTimedOut: allTimedOut && respondedCount == 0,
			}
		}
	}

	return ScanResult{ip: ip, allTimedOut: true}
}

func formatResults(results []PortResult) (summary string, detail string) {
	var activePorts []string
	var details []string

	for _, r := range results {
		if r.responded {
			activePorts = append(activePorts, r.port)
			size := "unknown size"
			if r.bytesSent >= 0 {
				size = fmt.Sprintf("%d bytes", r.bytesSent)
			}
			details = append(details, fmt.Sprintf("%s/%s → %d (%s)",
				r.scheme, r.port, r.status, size))
		}
	}

	summary = strings.Join(activePorts, ", ")
	detail = strings.Join(details, " | ")
	return
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: scanner <CIDR>")
		fmt.Println("Example: scanner 104.16.0.0/16")
		os.Exit(1)
	}

	cidr := os.Args[1]
	jobs, total, err := ipGenerator(cidr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid CIDR: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[*] Scanning ~%d hosts in %s\n", total, cidr)
	fmt.Printf("[*] Host header: %s\n", zeroRatedHost)
	fmt.Printf("[*] Workers: %d | Rate: %d IPs/s\n\n", workers, ratePerSec)

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("scan_%s_%s.txt", strings.ReplaceAll(cidr, "/", "-"), timestamp)
	outFile, err := os.Create(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot create output file: %v\n", err)
		os.Exit(1)
	}
	defer outFile.Close()
	writer := bufio.NewWriter(outFile)
	defer writer.Flush()

	fmt.Fprintf(writer, "# GET scan of %s\n", cidr)
	fmt.Fprintf(writer, "# Host header: %s\n", zeroRatedHost)
	fmt.Fprintf(writer, "# Started: %s\n\n", timestamp)
	fmt.Fprintf(writer, "%-18s %-12s %s\n", "IP", "Ports", "Detail")
	fmt.Fprintf(writer, "%s\n", strings.Repeat("-", 70))

	ticker := time.NewTicker(time.Second / ratePerSec)
	defer ticker.Stop()

	var mu sync.Mutex
	var wg sync.WaitGroup
	found, scanned, softblocks := 0, 0, 0

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				<-ticker.C
				result := scanIP(ip)

				mu.Lock()
				scanned++

				switch {
				case result.allTimedOut:
					softblocks++
					if softblocks%10 == 0 {
						fmt.Printf("[~] softblock events: %d (last: %s)\n", softblocks, ip)
					}

				default:
					summary, detail := formatResults(result.ports)
					if summary != "" {
						found++
						fmt.Printf("[+] %-16s  ports: %-12s %s\n", ip, summary, detail)
						fmt.Fprintf(writer, "%-18s %-12s %s\n", ip, summary, detail)
						writer.Flush()
					}
				}

				if scanned%100 == 0 {
					fmt.Printf("    progress: %d/%d | found: %d | softblocks: %d\n",
						scanned, total, found, softblocks)
				}
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	fmt.Fprintf(writer, "\n%s\n", strings.Repeat("-", 70))
	fmt.Fprintf(writer, "# Done. %d responsive | %d softblock events\n", found, softblocks)
	fmt.Printf("\n[*] Done. %d/%d | %d responded | %d softblocks → %s\n",
		scanned, total, found, softblocks, filename)
}
