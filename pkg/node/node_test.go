package node

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/systemshift/hashpool/pkg/commitment"
	"github.com/systemshift/hashpool/pkg/pow"
)

func TestNewNode(t *testing.T) {
	ctx := context.Background()

	n, err := New(ctx, Config{
		ListenPort: 0,
		Difficulty: 8,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer n.host.Close()

	if n.Difficulty() != 8 {
		t.Errorf("Expected difficulty 8, got %d", n.Difficulty())
	}
}

func TestNodeStartStop(t *testing.T) {
	ctx := context.Background()

	n, err := New(ctx, Config{
		ListenPort:    0,
		Difficulty:    8,
		RoundInterval: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := n.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Should not start twice
	if err := n.Start(ctx); err == nil {
		t.Error("Expected error when starting twice")
	}

	if err := n.Stop(); err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}

func TestNodeSubmit(t *testing.T) {
	ctx := context.Background()

	n, err := New(ctx, Config{
		ListenPort:    0,
		Difficulty:    8,
		RoundInterval: time.Hour, // Long interval to prevent auto-flush
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if err := n.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer n.Stop()

	hash := sha256.Sum256([]byte("test submission"))
	challenge := pow.Solve(hash, 8)

	if err := n.Submit(hash, challenge.Nonce); err != nil {
		t.Errorf("Submit() error = %v", err)
	}

	if n.Mempool().Count() != 1 {
		t.Errorf("Expected mempool size 1, got %d", n.Mempool().Count())
	}
}

func TestTwoNodesCommunicate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create two nodes
	n1, err := New(ctx, Config{
		ListenPort:    0,
		Difficulty:    8,
		RoundInterval: 500 * time.Millisecond,
		Verbose:       false,
	})
	if err != nil {
		t.Fatalf("New() node1 error = %v", err)
	}

	n2, err := New(ctx, Config{
		ListenPort:    0,
		Difficulty:    8,
		RoundInterval: 500 * time.Millisecond,
		Verbose:       false,
	})
	if err != nil {
		t.Fatalf("New() node2 error = %v", err)
	}

	// Start both nodes
	if err := n1.Start(ctx); err != nil {
		t.Fatalf("Start() node1 error = %v", err)
	}
	defer n1.Stop()

	if err := n2.Start(ctx); err != nil {
		t.Fatalf("Start() node2 error = %v", err)
	}
	defer n2.Stop()

	// Connect node2 to node1
	addrs := n1.Host().Addrs()
	if len(addrs) == 0 {
		t.Fatal("Node1 has no addresses")
	}
	connectAddr := addrs[0].String() + "/p2p/" + n1.Host().ID().String()

	if err := n2.Connect(ctx, connectAddr); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}

	// Wait for pubsub to establish mesh
	time.Sleep(100 * time.Millisecond)

	// Submit hash to node1
	hash := sha256.Sum256([]byte("gossip test"))
	challenge := pow.Solve(hash, 8)

	if err := n1.Submit(hash, challenge.Nonce); err != nil {
		t.Fatalf("Submit() error = %v", err)
	}

	// Wait for gossip propagation
	time.Sleep(200 * time.Millisecond)

	// Node2 should have received it
	if n2.Mempool().Count() != 1 {
		t.Errorf("Expected node2 mempool size 1, got %d", n2.Mempool().Count())
	}
}

func TestCommitmentCallback(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	n, err := New(ctx, Config{
		ListenPort:    0,
		Difficulty:    8,
		RoundInterval: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	commitmentReceived := make(chan struct{})
	n.SetOnCommitment(func(c *commitment.Commitment) {
		if len(c.Hashes) > 0 {
			close(commitmentReceived)
		}
	})

	if err := n.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer n.Stop()

	// Submit a hash
	hash := sha256.Sum256([]byte("commitment test"))
	challenge := pow.Solve(hash, 8)
	_ = n.Submit(hash, challenge.Nonce)

	// Wait for commitment
	select {
	case <-commitmentReceived:
		// Success
	case <-time.After(500 * time.Millisecond):
		t.Error("Commitment callback not called within timeout")
	}
}
