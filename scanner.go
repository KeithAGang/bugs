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
	workers    = 10
	ratePerSec = 12 // conservative — helps avoid DNS softblock
	timeout    = 4 * time.Second
	retryDelay = 2 * time.Second // wait before retrying after a suspected softblock
	retryMax   = 2               // max retries per IP on timeout
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

// probePort attempts a TCP dial and classifies the result
func probePort(ip, port string) PortResult {
	conn, err := net.DialTimeout("tcp", ip+":"+port, timeout)
	if err == nil {
		conn.Close()
		return PortResult{port: port, alive: true, timedOut: false}
	}

	errStr := err.Error()

	// connection refused = host is alive, just no service on this port
	if strings.Contains(errStr, "connection refused") {
		return PortResult{port: port, alive: true, timedOut: false}
	}

	// i/o timeout or context deadline = possible softblock or truly dead
	if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline") {
		return PortResult{port: port, alive: false, timedOut: true}
	}

	return PortResult{port: port, alive: false, timedOut: false}
}

type ScanResult struct {
	ip          string
	openPorts   []string
	allTimedOut bool // true if every port timed out — softblock signal
}

// scanIP probes all 3 ports, with retry logic on full-timeout results
func scanIP(ip string) ScanResult {
	result := ScanResult{ip: ip}

	for attempt := 0; attempt <= retryMax; attempt++ {
		if attempt > 0 {
			// all ports timed out on previous attempt — likely softblock, back off
			fmt.Printf("[!] Soft-block suspected on %s, backing off %v (attempt %d/%d)\n",
				ip, retryDelay, attempt, retryMax)
			time.Sleep(retryDelay)
		}

		var openPorts []string
		timeoutCount := 0

		for _, port := range ports {
			res := probePort(ip, port)
			if res.alive {
				openPorts = append(openPorts, port)
			}
			if res.timedOut {
				timeoutCount++
			}
		}

		allTimedOut := timeoutCount == len(ports)

		if !allTimedOut || attempt == retryMax {
			// got a real result, or exhausted retries
			result.openPorts = openPorts
			result.allTimedOut = allTimedOut && len(openPorts) == 0
			return result
		}
		// all timed out and retries remain — loop and back off
	}

	return result
}

func formatPorts(ports []string) string {
	if len(ports) == 0 {
		return "none"
	}
	return strings.Join(ports, ", ")
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
	fmt.Printf("[*] Workers: %d | Rate: %d req/s | Ports: %s\n\n",
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

	fmt.Fprintf(writer, "# TCP scan of %s\n", cidr)
	fmt.Fprintf(writer, "# Started: %s\n", timestamp)
	fmt.Fprintf(writer, "# Ports tested: %s\n\n", strings.Join(ports, ", "))
	fmt.Fprintf(writer, "%-18s %s\n", "IP", "Open Ports")
	fmt.Fprintf(writer, "%s\n", strings.Repeat("-", 40))

	ticker := time.NewTicker(time.Second / ratePerSec)
	defer ticker.Stop()

	var wg sync.WaitGroup
	var mu sync.Mutex
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

				if result.allTimedOut {
					softblocks++
					fmt.Printf("[~] %-16s  all ports timed out after retries (softblocks: %d)\n",
						ip, softblocks)
				} else if len(result.openPorts) > 0 {
					found++
					portStr := formatPorts(result.openPorts)
					fmt.Printf("[+] %-16s  ports: %-20s (%d found)\n",
						ip, portStr, found)
					fmt.Fprintf(writer, "%-18s %s\n", ip, portStr)
					writer.Flush()
				}

				if scanned%200 == 0 {
					fmt.Printf("    progress: %d/%d | found: %d | softblocks: %d\n",
						scanned, total, found, softblocks)
				}
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	fmt.Fprintf(writer, "\n%s\n", strings.Repeat("-", 40))
	fmt.Fprintf(writer, "# Done. %d responsive hosts | %d softblock events\n", found, softblocks)
	fmt.Printf("\n[*] Done. %d/%d scanned | %d alive | %d softblock events → %s\n",
		scanned, total, found, softblocks, filename)
}
