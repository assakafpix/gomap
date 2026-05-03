// Command gomap is an nmap-compatible service-version scanner that routes
// every TCP probe through an optional SOCKS5 proxy.
//
// CLI surface lives in args.go (flag definitions, reorderArgs, usage).
// Target list construction lives in targets.go.
// Output formatting lives in output.go.
// This file is just the entry point and the scan-execution loop.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/assakafpix/gomap/pkg/dialer"
	"github.com/assakafpix/gomap/pkg/nmapprobe"
	"github.com/assakafpix/gomap/pkg/ports"
)

const version = "1.2.0"

func main() {
	opts, ok := parseArgs(os.Args[0], os.Args[1:])
	if !ok {
		os.Exit(1)
	}
	if opts.exitImmediately {
		return
	}

	if !opts.silent {
		fmt.Fprintf(os.Stderr, "Starting gomap %s ( https://github.com/assakafpix/gomap ) at %s\n",
			version, time.Now().Format("2006-01-02 15:04 MST"))
	}

	targets, err := collectTargets(opts)
	if err != nil {
		log.Fatal(err)
	}
	if len(targets) == 0 {
		usage(os.Args[0])
		os.Exit(1)
	}

	engine, err := buildEngine(opts)
	if err != nil {
		log.Fatal(err)
	}

	announceScan(opts, len(targets))

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	results := runScans(ctx, engine, targets, opts)
	emit(results, opts.jsonOut)
}

// buildEngine sets up the dialer and probe DB. The probe DB is only loaded
// when -sV is requested — without it, the engine just does a TCP connect
// liveness check, so paying for 12k regex compilations would be waste.
func buildEngine(opts *cliOptions) (*nmapprobe.Engine, error) {
	d, err := dialer.New(opts.proxyURL, opts.timeout)
	if err != nil {
		return nil, fmt.Errorf("create dialer: %w", err)
	}

	if !opts.serviceVersionScan {
		return nmapprobe.NewEngine(nil, d, opts.timeout, 0), nil
	}

	if !opts.silent {
		fmt.Fprintf(os.Stderr, "[*] Loading nmap probe database...")
	}
	engine, err := nmapprobe.DefaultEngine(d, opts.timeout, opts.intensity)
	if err != nil {
		return nil, fmt.Errorf("load nmap probes: %w", err)
	}
	if !opts.silent {
		total := 0
		for _, p := range engine.Probes {
			total += len(p.Matches) + len(p.SoftMatches)
		}
		fmt.Fprintf(os.Stderr, " %d probes, %d signatures loaded\n", len(engine.Probes), total)
	}
	return engine, nil
}

// announceScan prints the scan banner ([*] Using proxy / [*] Scanning ...).
// Suppressed in --silent mode.
func announceScan(opts *cliOptions, targetCount int) {
	if opts.silent {
		return
	}
	if opts.proxyURL != "" {
		fmt.Fprintf(os.Stderr, "[*] Using SOCKS5 proxy: %s\n", dialer.MaskCredentials(opts.proxyURL))
	}
	mode := "open-port scan (no version detection — pass -sV to probe)"
	if opts.serviceVersionScan {
		mode = fmt.Sprintf("service/version detection (intensity=%d)", opts.intensity)
	}
	fmt.Fprintf(os.Stderr, "[*] Scanning %d target(s), parallelism=%d, %s\n\n",
		targetCount, opts.concurrency, mode)
}

// runScans fans the target list out across `concurrency` goroutines and
// returns a buffered channel that the caller drains. Each goroutine picks
// the right detect path based on opts.serviceVersionScan.
func runScans(ctx context.Context, engine *nmapprobe.Engine, targets []target, opts *cliOptions) <-chan nmapprobe.DetectResult {
	results := make(chan nmapprobe.DetectResult, len(targets))
	sem := make(chan struct{}, opts.concurrency)
	var wg sync.WaitGroup

	for _, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(t target) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			results <- detectOne(ctx, engine, t, opts.serviceVersionScan)
		}(t)
	}

	go func() { wg.Wait(); close(results) }()
	return results
}

// detectOne runs the right detection path for a single target. Without -sV
// we just liveness-check + annotate with the IANA-ish name; with -sV we
// run the full probe cascade.
func detectOne(ctx context.Context, engine *nmapprobe.Engine, t target, withVersion bool) nmapprobe.DetectResult {
	if withVersion {
		return engine.Detect(ctx, t.host, t.port)
	}
	r := engine.DetectOpen(ctx, t.host, t.port)
	if r.Open {
		r.Protocol = ports.ServiceName(t.port)
	}
	return r
}

// emit drains the result channel, skipping closed ports and writing each
// open one in the requested format.
func emit(results <-chan nmapprobe.DetectResult, jsonOut bool) {
	enc := json.NewEncoder(os.Stdout)
	for result := range results {
		if !result.Open {
			continue
		}
		if jsonOut {
			enc.Encode(result)
		} else {
			printResult(result)
		}
	}
}
