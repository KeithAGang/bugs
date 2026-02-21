package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

const (
	workers    = 10
	ratePerSec = 15
	timeout    = 5 * time.Second
)

// ipGenerator streams IPs from a CIDR into a channel — no full slice in memory
func ipGenerator(cidr string) (<-chan string, int, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, 0, err
	}

	// Calculate total count for progress display
	ones, bits := ipNet.Mask.Size()
	total := (1 << (bits - ones)) - 2 // exclude network + broadcast
	if total < 0 {
		total = 0
	}

	ch := make(chan string, workers*2) // small buffer, not the full list

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

func checkIP(ip string, client *http.Client) bool {
	resp, err := client.Head("http://" + ip)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode < 600
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: scanner <CIDR>")
		fmt.Println("Example: scanner 41.222.192.0/18")
		os.Exit(1)
	}

	cidr := os.Args[1]
	jobs, total, err := ipGenerator(cidr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid CIDR: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[*] Scanning ~%d hosts in %s\n", total, cidr)
	fmt.Printf("[*] Workers: %d | Rate limit: %d req/s\n", workers, ratePerSec)

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("scan_%s.txt", timestamp)
	outFile, err := os.Create(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot create output file: %v\n", err)
		os.Exit(1)
	}
	defer outFile.Close()
	writer := bufio.NewWriter(outFile)
	defer writer.Flush()

	fmt.Fprintf(writer, "# Scan of %s started at %s\n\n", cidr, timestamp)

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	ticker := time.NewTicker(time.Second / ratePerSec)
	defer ticker.Stop()

	var wg sync.WaitGroup
	var mu sync.Mutex
	found := 0
	scanned := 0

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				<-ticker.C
				responsive := checkIP(ip, client)

				mu.Lock()
				scanned++
				if responsive {
					found++
					fmt.Printf("[+] %-16s  (%d scanned, %d found)\n", ip, scanned, found)
					fmt.Fprintln(writer, ip)
					writer.Flush()
				} else if scanned%500 == 0 {
					fmt.Printf("[-] Progress: %d/%d scanned, %d found\n", scanned, total, found)
				}
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	fmt.Fprintf(writer, "\n# Scan complete. %d responsive hosts found.\n", found)
	fmt.Printf("\n[*] Done. %d/%d scanned, %d responsive hosts → %s\n", scanned, total, found, filename)
}
