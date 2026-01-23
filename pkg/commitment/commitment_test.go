package commitment

import (
	"crypto/sha256"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	hashes := make([][32]byte, 5)
	for i := range hashes {
		hashes[i] = sha256.Sum256([]byte{byte(i)})
	}

	c, err := New(1, time.Now(), hashes, "test-node")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if c.Round != 1 {
		t.Errorf("Expected round 1, got %d", c.Round)
	}

	if c.NodeID != "test-node" {
		t.Errorf("Expected node_id 'test-node', got %s", c.NodeID)
	}

	var zero [32]byte
	if c.Root == zero {
		t.Error("Root should not be zero")
	}

	if len(c.Hashes) != 5 {
		t.Errorf("Expected 5 hashes, got %d", len(c.Hashes))
	}
}

func TestNewEmpty(t *testing.T) {
	_, err := New(1, time.Now(), nil, "test-node")
	if err != ErrNoHashes {
		t.Errorf("Expected ErrNoHashes, got %v", err)
	}
}

func TestVerify(t *testing.T) {
	hashes := make([][32]byte, 3)
	for i := range hashes {
		hashes[i] = sha256.Sum256([]byte{byte(i)})
	}

	c, _ := New(1, time.Now(), hashes, "test-node")

	if err := c.Verify(); err != nil {
		t.Errorf("Verify() error = %v", err)
	}
}

func TestVerifyTampered(t *testing.T) {
	hashes := make([][32]byte, 3)
	for i := range hashes {
		hashes[i] = sha256.Sum256([]byte{byte(i)})
	}

	c, _ := New(1, time.Now(), hashes, "test-node")

	// Tamper with the root
	c.Root[0] ^= 0xFF

	if err := c.Verify(); err != ErrInvalidRoot {
		t.Errorf("Expected ErrInvalidRoot, got %v", err)
	}
}

func TestContains(t *testing.T) {
	hashes := make([][32]byte, 3)
	for i := range hashes {
		hashes[i] = sha256.Sum256([]byte{byte(i)})
	}

	c, _ := New(1, time.Now(), hashes, "test-node")

	// Should contain all original hashes
	for _, h := range hashes {
		if !c.Contains(h) {
			t.Errorf("Commitment should contain hash %x", h[:8])
		}
	}

	// Should not contain a different hash
	notInCommitment := sha256.Sum256([]byte{255})
	if c.Contains(notInCommitment) {
		t.Error("Commitment should not contain hash 255")
	}
}

func TestProofFor(t *testing.T) {
	hashes := make([][32]byte, 5)
	for i := range hashes {
		hashes[i] = sha256.Sum256([]byte{byte(i)})
	}

	c, _ := New(1, time.Now(), hashes, "test-node")

	// Generate and verify proof for each hash
	for _, h := range hashes {
		proof, err := c.ProofFor(h)
		if err != nil {
			t.Errorf("ProofFor() error = %v", err)
			continue
		}

		if err := proof.Verify(c.Root); err != nil {
			t.Errorf("Proof.Verify() error = %v", err)
		}
	}
}

func TestInclusionProof(t *testing.T) {
	hashes := make([][32]byte, 4)
	for i := range hashes {
		hashes[i] = sha256.Sum256([]byte{byte(i)})
	}

	c, _ := New(1, time.Now(), hashes, "test-node")

	proof, err := c.NewInclusionProof(hashes[0])
	if err != nil {
		t.Fatalf("NewInclusionProof() error = %v", err)
	}

	if err := proof.Verify(); err != nil {
		t.Errorf("InclusionProof.Verify() error = %v", err)
	}
}

func TestDrandProof(t *testing.T) {
	hashes := make([][32]byte, 2)
	for i := range hashes {
		hashes[i] = sha256.Sum256([]byte{byte(i)})
	}

	c, _ := New(1, time.Now(), hashes, "test-node")

	randomness := []byte("random")
	signature := []byte("signature")
	c.SetDrandProof(randomness, signature)

	if string(c.DrandRandomness) != "random" {
		t.Error("DrandRandomness not set correctly")
	}

	if string(c.DrandSignature) != "signature" {
		t.Error("DrandSignature not set correctly")
	}
}

func TestDeterministicCommitment(t *testing.T) {
	// Same hashes in different order should produce same root
	hashes1 := [][32]byte{
		sha256.Sum256([]byte("a")),
		sha256.Sum256([]byte("b")),
		sha256.Sum256([]byte("c")),
	}

	hashes2 := [][32]byte{
		sha256.Sum256([]byte("c")),
		sha256.Sum256([]byte("a")),
		sha256.Sum256([]byte("b")),
	}

	ts := time.Now()
	c1, _ := New(1, ts, hashes1, "node")
	c2, _ := New(1, ts, hashes2, "node")

	if c1.Root != c2.Root {
		t.Error("Same hashes in different order should produce same root")
	}
}
