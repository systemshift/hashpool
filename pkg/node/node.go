// Package node implements a P2P hashpool node using libp2p
package node

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	"github.com/systemshift/hashpool/pkg/commitment"
	"github.com/systemshift/hashpool/pkg/mempool"
)

const (
	// Topic names for pubsub
	TopicSubmissions = "/hashpool/submissions/1.0.0"
	TopicCommitments = "/hashpool/commitments/1.0.0"
)

// Config holds node configuration
type Config struct {
	// Network
	ListenPort int
	BootstrapPeers []string

	// Mempool
	Difficulty uint8

	// Timing
	RoundInterval time.Duration // How often to commit (should align with drand)

	// Optional
	Verbose bool
}

// Node represents a hashpool P2P node
type Node struct {
	cfg     Config
	host    host.Host
	ps      *pubsub.PubSub
	mempool *mempool.Mempool

	// Pubsub topics
	subTopic    *pubsub.Topic
	commitTopic *pubsub.Topic
	subSub      *pubsub.Subscription
	commitSub   *pubsub.Subscription

	// State
	mu          sync.RWMutex
	commitments []*commitment.Commitment
	running     bool
	ctx         context.Context // lifecycle ctx; set on Start
	cancel      context.CancelFunc
	wg          sync.WaitGroup // tracks the three handler goroutines

	// callbackWG tracks in-flight onCommitment callback goroutines so
	// Stop can wait for them to drain before tearing down resources.
	callbackWG sync.WaitGroup

	// Callbacks
	onCommitment func(*commitment.Commitment)
}

// SubmissionMessage is sent over the submissions topic
type SubmissionMessage struct {
	Hash  [32]byte `json:"hash"`
	Nonce uint64   `json:"nonce"`
}

// New creates a new hashpool node
func New(ctx context.Context, cfg Config) (*Node, error) {
	// Set defaults
	if cfg.RoundInterval == 0 {
		cfg.RoundInterval = 10 * time.Second
	}
	if cfg.Difficulty == 0 {
		cfg.Difficulty = 16
	}

	// Create libp2p host
	listenAddr := fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", cfg.ListenPort)
	h, err := libp2p.New(
		libp2p.ListenAddrStrings(listenAddr),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create host: %w", err)
	}

	// Create pubsub
	ps, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		h.Close()
		return nil, fmt.Errorf("failed to create pubsub: %w", err)
	}

	// Join topics
	subTopic, err := ps.Join(TopicSubmissions)
	if err != nil {
		h.Close()
		return nil, fmt.Errorf("failed to join submissions topic: %w", err)
	}

	commitTopic, err := ps.Join(TopicCommitments)
	if err != nil {
		h.Close()
		return nil, fmt.Errorf("failed to join commitments topic: %w", err)
	}

	// Subscribe to topics
	subSub, err := subTopic.Subscribe()
	if err != nil {
		h.Close()
		return nil, fmt.Errorf("failed to subscribe to submissions: %w", err)
	}

	commitSub, err := commitTopic.Subscribe()
	if err != nil {
		h.Close()
		return nil, fmt.Errorf("failed to subscribe to commitments: %w", err)
	}

	// Create mempool
	mp := mempool.New(mempool.Config{
		Difficulty: cfg.Difficulty,
	})

	n := &Node{
		cfg:         cfg,
		host:        h,
		ps:          ps,
		mempool:     mp,
		subTopic:    subTopic,
		commitTopic: commitTopic,
		subSub:      subSub,
		commitSub:   commitSub,
		commitments: make([]*commitment.Commitment, 0),
	}

	// Set mempool callback to gossip new submissions
	mp.SetOnSubmit(func(sub *mempool.Submission) {
		n.gossipSubmission(sub)
	})

	return n, nil
}

// Start begins node operation
func (n *Node) Start(ctx context.Context) error {
	n.mu.Lock()
	if n.running {
		n.mu.Unlock()
		return fmt.Errorf("node already running")
	}

	ctx, cancel := context.WithCancel(ctx)
	n.ctx = ctx
	n.cancel = cancel
	n.running = true
	n.mu.Unlock()

	// Connect to bootstrap peers
	for _, addr := range n.cfg.BootstrapPeers {
		if err := n.Connect(ctx, addr); err != nil {
			log.Printf("Failed to connect to bootstrap peer %s: %v", addr, err)
		}
	}

	// Start handlers
	n.wg.Add(3)
	go n.handleSubmissions(ctx)
	go n.handleCommitments(ctx)
	go n.roundLoop(ctx)

	if n.cfg.Verbose {
		log.Printf("Node started: %s", n.host.ID())
		for _, addr := range n.host.Addrs() {
			log.Printf("  Listening on: %s/p2p/%s", addr, n.host.ID())
		}
	}

	return nil
}

// Stop stops the node and tears down pubsub state. It blocks until
// handler goroutines and any in-flight onCommitment callbacks have
// finished, then leaves the pubsub topics and closes the host.
func (n *Node) Stop() error {
	n.mu.Lock()
	if !n.running {
		n.mu.Unlock()
		return nil
	}
	n.cancel()
	n.running = false
	n.mu.Unlock()

	// Cancel subscriptions so subSub.Next/commitSub.Next return
	// (ctx cancellation alone is enough to make Next return, but
	// Cancel also releases the subscription's internal state).
	n.subSub.Cancel()
	n.commitSub.Cancel()

	// Wait for handler goroutines to exit before leaving topics —
	// otherwise a handler could still be touching topic state.
	n.wg.Wait()

	// Wait for any in-flight commitment callbacks to drain so the
	// caller's Stop() can safely tear down state the callbacks reference.
	n.callbackWG.Wait()

	// Leave the pubsub topics. Errors here are non-fatal — host.Close
	// will clean up anything that's left.
	var topicErrs []error
	if err := n.subTopic.Close(); err != nil {
		topicErrs = append(topicErrs, fmt.Errorf("close submissions topic: %w", err))
	}
	if err := n.commitTopic.Close(); err != nil {
		topicErrs = append(topicErrs, fmt.Errorf("close commitments topic: %w", err))
	}

	n.mempool.Close()

	if err := n.host.Close(); err != nil {
		topicErrs = append(topicErrs, fmt.Errorf("close host: %w", err))
	}

	if len(topicErrs) > 0 {
		return fmt.Errorf("errors during shutdown: %v", topicErrs)
	}
	return nil
}

// Connect connects to a peer by multiaddr string
func (n *Node) Connect(ctx context.Context, addrStr string) error {
	addr, err := multiaddr.NewMultiaddr(addrStr)
	if err != nil {
		return fmt.Errorf("invalid multiaddr: %w", err)
	}

	info, err := peer.AddrInfoFromP2pAddr(addr)
	if err != nil {
		return fmt.Errorf("failed to parse peer info: %w", err)
	}

	if err := n.host.Connect(ctx, *info); err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	if n.cfg.Verbose {
		log.Printf("Connected to peer: %s", info.ID)
	}

	return nil
}

// Submit submits a hash to the mempool
func (n *Node) Submit(hash [32]byte, nonce uint64) error {
	return n.mempool.Submit(hash, nonce)
}

// Difficulty returns the current PoW difficulty
func (n *Node) Difficulty() uint8 {
	return n.mempool.Difficulty()
}

// SetOnCommitment sets a callback for new commitments. The callback is
// invoked in a separate goroutine for each commitment; panics inside
// the callback are recovered and logged so they cannot crash the node.
func (n *Node) SetOnCommitment(fn func(*commitment.Commitment)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.onCommitment = fn
}

// runCallback dispatches an onCommitment callback in a tracked goroutine
// with panic recovery. Stop() waits on callbackWG before tearing down state.
func (n *Node) runCallback(callback func(*commitment.Commitment), c *commitment.Commitment) {
	n.callbackWG.Add(1)
	go func() {
		defer n.callbackWG.Done()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("commitment callback panicked: %v", r)
			}
		}()
		callback(c)
	}()
}

// Commitments returns all stored commitments
func (n *Node) Commitments() []*commitment.Commitment {
	n.mu.RLock()
	defer n.mu.RUnlock()
	result := make([]*commitment.Commitment, len(n.commitments))
	copy(result, n.commitments)
	return result
}

// Host returns the libp2p host
func (n *Node) Host() host.Host {
	return n.host
}

// Mempool returns the mempool
func (n *Node) Mempool() *mempool.Mempool {
	return n.mempool
}

// publishTimeout bounds a single Publish call so a hung pubsub mesh
// can't pin a goroutine indefinitely.
const publishTimeout = 5 * time.Second

// gossipSubmission broadcasts a submission to peers. It uses the node's
// lifecycle ctx (set by Start) so a Publish in flight aborts when Stop is
// called. If invoked before Start, the call is skipped — there are no
// peers to gossip to yet.
func (n *Node) gossipSubmission(sub *mempool.Submission) {
	n.mu.RLock()
	parent := n.ctx
	n.mu.RUnlock()
	if parent == nil {
		return
	}

	msg := SubmissionMessage{
		Hash:  sub.Hash,
		Nonce: sub.Nonce,
	}

	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("Failed to marshal submission: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(parent, publishTimeout)
	defer cancel()

	if err := n.subTopic.Publish(ctx, data); err != nil {
		log.Printf("Failed to publish submission: %v", err)
	}
}

// handleSubmissions processes incoming submissions from peers
func (n *Node) handleSubmissions(ctx context.Context) {
	defer n.wg.Done()

	for {
		msg, err := n.subSub.Next(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("Error receiving submission: %v", err)
			continue
		}

		// Ignore our own messages
		if msg.ReceivedFrom == n.host.ID() {
			continue
		}

		var sub SubmissionMessage
		if err := json.Unmarshal(msg.Data, &sub); err != nil {
			log.Printf("Failed to unmarshal submission: %v", err)
			continue
		}

		// Add to mempool (from peer, so no callback)
		if err := n.mempool.SubmitFromPeer(sub.Hash, sub.Nonce); err != nil {
			// Duplicates and invalid PoW are expected, don't log
			continue
		}

		if n.cfg.Verbose {
			log.Printf("Received submission from %s", msg.ReceivedFrom.ShortString())
		}
	}
}

// handleCommitments processes incoming commitments from peers
func (n *Node) handleCommitments(ctx context.Context) {
	defer n.wg.Done()

	for {
		msg, err := n.commitSub.Next(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("Error receiving commitment: %v", err)
			continue
		}

		// Ignore our own messages
		if msg.ReceivedFrom == n.host.ID() {
			continue
		}

		var c commitment.Commitment
		if err := json.Unmarshal(msg.Data, &c); err != nil {
			log.Printf("Failed to unmarshal commitment: %v", err)
			continue
		}

		// Verify commitment
		if err := c.Verify(); err != nil {
			log.Printf("Invalid commitment from %s: %v", msg.ReceivedFrom.ShortString(), err)
			continue
		}

		// Store commitment
		n.mu.Lock()
		n.commitments = append(n.commitments, &c)
		callback := n.onCommitment
		n.mu.Unlock()

		if callback != nil {
			n.runCallback(callback, &c)
		}

		if n.cfg.Verbose {
			log.Printf("Received commitment for round %d from %s (%d hashes)",
				c.Round, msg.ReceivedFrom.ShortString(), len(c.Hashes))
		}
	}
}

// roundLoop creates commitments at regular intervals
func (n *Node) roundLoop(ctx context.Context) {
	defer n.wg.Done()

	ticker := time.NewTicker(n.cfg.RoundInterval)
	defer ticker.Stop()

	// Calculate round number based on interval
	// Use milliseconds to avoid divide by zero for sub-second intervals
	intervalMs := n.cfg.RoundInterval.Milliseconds()
	if intervalMs == 0 {
		intervalMs = 1
	}
	round := uint64(time.Now().UnixMilli() / intervalMs)

	for {
		select {
		case <-ctx.Done():
			return
		case t := <-ticker.C:
			round++
			n.createCommitment(ctx, round, t)
		}
	}
}

// createCommitment creates and broadcasts a commitment for the current round
func (n *Node) createCommitment(ctx context.Context, round uint64, timestamp time.Time) {
	// Flush mempool
	submissions := n.mempool.Flush()
	if len(submissions) == 0 {
		if n.cfg.Verbose {
			log.Printf("Round %d: no hashes to commit", round)
		}
		return
	}

	// Extract hashes
	hashes := make([][32]byte, len(submissions))
	for i, sub := range submissions {
		hashes[i] = sub.Hash
	}

	// Create commitment
	c, err := commitment.New(round, timestamp, hashes, n.host.ID().String())
	if err != nil {
		log.Printf("Failed to create commitment: %v", err)
		return
	}

	// Store locally
	n.mu.Lock()
	n.commitments = append(n.commitments, c)
	callback := n.onCommitment
	n.mu.Unlock()

	if callback != nil {
		n.runCallback(callback, c)
	}

	// Broadcast
	data, err := json.Marshal(c)
	if err != nil {
		log.Printf("Failed to marshal commitment: %v", err)
		return
	}

	if err := n.commitTopic.Publish(ctx, data); err != nil {
		log.Printf("Failed to publish commitment: %v", err)
		return
	}

	if n.cfg.Verbose {
		log.Printf("Round %d: committed %d hashes, root: %x...",
			round, len(hashes), c.Root[:8])
	}
}
