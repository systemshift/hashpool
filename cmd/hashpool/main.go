// Command hashpool runs a hashpool P2P node
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/systemshift/hashpool/pkg/commitment"
	"github.com/systemshift/hashpool/pkg/node"
	"github.com/systemshift/hashpool/pkg/pow"
)

func main() {
	// Parse flags
	port := flag.Int("port", 0, "Listen port (0 for random)")
	peer := flag.String("peer", "", "Bootstrap peer multiaddr")
	difficulty := flag.Int("difficulty", 16, "PoW difficulty (leading zero bits)")
	interval := flag.Duration("interval", 10*time.Second, "Round interval")
	verbose := flag.Bool("verbose", false, "Verbose logging")

	// Client mode flags
	submit := flag.String("submit", "", "Submit a hash (hex string or file path)")

	flag.Parse()

	// If submitting, run client mode
	if *submit != "" {
		runClient(*submit, *peer, uint8(*difficulty))
		return
	}

	// Run node
	runNode(*port, *peer, uint8(*difficulty), *interval, *verbose)
}

func runNode(port int, peer string, difficulty uint8, interval time.Duration, verbose bool) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Build config
	cfg := node.Config{
		ListenPort:    port,
		Difficulty:    difficulty,
		RoundInterval: interval,
		Verbose:       verbose,
	}
	if peer != "" {
		cfg.BootstrapPeers = []string{peer}
	}

	// Create node
	n, err := node.New(ctx, cfg)
	if err != nil {
		log.Fatalf("Failed to create node: %v", err)
	}

	// Set commitment callback
	n.SetOnCommitment(func(c *commitment.Commitment) {
		log.Printf("Commitment round %d: %d hashes, root: %x",
			c.Round, len(c.Hashes), c.Root[:8])
	})

	// Start node
	if err := n.Start(ctx); err != nil {
		log.Fatalf("Failed to start node: %v", err)
	}

	log.Printf("Hashpool node started")
	log.Printf("  Port: %d", port)
	log.Printf("  Difficulty: %d bits (~%d hashes)",
		difficulty, 1<<difficulty)
	log.Printf("  Round interval: %v", interval)

	// Print connection info
	for _, addr := range n.Host().Addrs() {
		log.Printf("  Connect: %s/p2p/%s", addr, n.Host().ID())
	}

	// Wait for shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("Received signal %v, shutting down...", sig)

	cancel()
	if err := n.Stop(); err != nil {
		log.Printf("Error stopping node: %v", err)
	}
	log.Printf("Shutdown complete")
}

func runClient(input string, nodeAddr string, difficulty uint8) {
	// Determine hash
	var hash [32]byte

	// Try as hex string first
	if decoded, err := hex.DecodeString(input); err == nil && len(decoded) == 32 {
		copy(hash[:], decoded)
	} else {
		// Try as file path
		data, err := os.ReadFile(input)
		if err != nil {
			// Treat as raw data
			data = []byte(input)
		}
		hash = sha256.Sum256(data)
	}

	log.Printf("Hash: %x", hash)
	log.Printf("Solving PoW with difficulty %d...", difficulty)

	start := time.Now()
	challenge := pow.Solve(hash, difficulty)
	elapsed := time.Since(start)

	log.Printf("Solved in %v (nonce: %d)", elapsed, challenge.Nonce)

	if nodeAddr == "" {
		// Just print the result
		fmt.Printf("Hash:  %x\n", hash)
		fmt.Printf("Nonce: %d\n", challenge.Nonce)
		fmt.Printf("To submit, run with -peer <node_addr>\n")
		return
	}

	// TODO: Submit to node via HTTP API or direct P2P connection
	log.Printf("Submission to remote nodes not yet implemented")
	log.Printf("For now, run your own node and submit locally")
}
