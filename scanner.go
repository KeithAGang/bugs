package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	workers    = 15
	ratePerSec = 20 // IPs per second, not port probes per second
	timeout    = 3 * time.Second
	retryDelay = 1500 * time.Millisecond
	retryMax   = 1
)

var ports = []string{"80", "443", "8080"}

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
	port     string
	alive    bool
	timedOut bool
}

func probePort(ip, port string) PortResult {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), timeout)
	if err == nil {
		conn.Close()
		return PortResult{port: port, alive: true}
	}

	e := err.Error()
	if strings.Contains(e, "connection refused") {
		return PortResult{port: port, alive: true}
	}
	if strings.Contains(e, "timeout") || strings.Contains(e, "deadline") {
		return PortResult{port: port, alive: false, timedOut: true}
	}
	return PortResult{port: port, alive: false}
}

type ScanResult struct {
	ip          string
	openPorts   []string
	allTimedOut bool
}

// scanIP probes all ports CONCURRENTLY then decides on retry
func scanIP(ip string) ScanResult {
	for attempt := 0; attempt <= retryMax; attempt++ {
		if attempt > 0 {
			time.Sleep(retryDelay)
		}

		results := make([]PortResult, len(ports))
		var wg sync.WaitGroup

		for i, port := range ports {
			wg.Add(1)
			go func(idx int, p string) {
				defer wg.Done()
				results[idx] = probePort(ip, p)
			}(i, port)
		}
		wg.Wait()

		var openPorts []string
		timeoutCount := 0
		for _, r := range results {
			if r.alive {
				openPorts = append(openPorts, r.port)
			}
			if r.timedOut {
				timeoutCount++
			}
		}

		allTimedOut := timeoutCount == len(ports)

		if !allTimedOut || attempt == retryMax {
			return ScanResult{
				ip:          ip,
				openPorts:   openPorts,
				allTimedOut: allTimedOut && len(openPorts) == 0,
			}
		}
	}

	return ScanResult{ip: ip, allTimedOut: true}
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
	fmt.Printf("[*] Workers: %d | Rate: %d IPs/s | Ports: %s\n\n",
		workers, ratePerSec, strings.Join(ports, ", "))

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

	fmt.Fprintf(writer, "# TCP scan of %s\n# Started: %s\n# Ports: %s\n\n",
		cidr, timestamp, strings.Join(ports, ", "))
	fmt.Fprintf(writer, "%-18s %s\n%s\n", "IP", "Open Ports", strings.Repeat("-", 40))

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
				<-ticker.C // one tick per IP — not per port probe
				result := scanIP(ip)

				mu.Lock()
				scanned++

				switch {
				case result.allTimedOut:
					softblocks++
					fmt.Printf("[~] %-16s  timed out (softblocks: %d)\n", ip, softblocks)

				case len(result.openPorts) > 0:
					found++
					portStr := strings.Join(result.openPorts, ", ")
					fmt.Printf("[+] %-16s  ports: %-20s (%d found)\n", ip, portStr, found)
					fmt.Fprintf(writer, "%-18s %s\n", ip, portStr)
					writer.Flush()
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

	fmt.Fprintf(writer, "\n%s\n# Done. %d responsive | %d softblock events\n",
		strings.Repeat("-", 40), found, softblocks)
	fmt.Printf("\n[*] Done. %d/%d | %d alive | %d softblocks → %s\n",
		scanned, total, found, softblocks, filename)
}
