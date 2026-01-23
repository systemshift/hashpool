// Package commitment implements round commitments with drand anchoring
package commitment

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/systemshift/hashpool/pkg/merkle"
)

var (
	ErrNoHashes       = errors.New("no hashes to commit")
	ErrInvalidRoot    = errors.New("computed root does not match")
	ErrHashNotInBatch = errors.New("hash not found in commitment")
)

// Commitment represents a batch of hashes committed at a drand round
type Commitment struct {
	// Round info
	Round     uint64    `json:"round"`
	Timestamp time.Time `json:"timestamp"`

	// Merkle commitment
	Root   [32]byte   `json:"root"`
	Hashes [][32]byte `json:"hashes"`

	// drand proof
	DrandRandomness []byte `json:"drand_randomness,omitempty"`
	DrandSignature  []byte `json:"drand_signature,omitempty"`

	// Node that created this commitment
	NodeID string `json:"node_id"`
}

// New creates a new commitment from a list of hashes
func New(round uint64, timestamp time.Time, hashes [][32]byte, nodeID string) (*Commitment, error) {
	if len(hashes) == 0 {
		return nil, ErrNoHashes
	}

	tree, err := merkle.NewTree(hashes)
	if err != nil {
		return nil, err
	}

	return &Commitment{
		Round:     round,
		Timestamp: timestamp,
		Root:      tree.Root(),
		Hashes:    tree.Leaves(), // Sorted
		NodeID:    nodeID,
	}, nil
}

// SetDrandProof adds the drand proof to the commitment
func (c *Commitment) SetDrandProof(randomness, signature []byte) {
	c.DrandRandomness = randomness
	c.DrandSignature = signature
}

// Verify checks that the commitment is valid
func (c *Commitment) Verify() error {
	if len(c.Hashes) == 0 {
		return ErrNoHashes
	}

	// Recompute merkle root
	tree, err := merkle.NewTree(c.Hashes)
	if err != nil {
		return err
	}

	if tree.Root() != c.Root {
		return ErrInvalidRoot
	}

	return nil
}

// Contains checks if a hash is in this commitment
func (c *Commitment) Contains(hash [32]byte) bool {
	for _, h := range c.Hashes {
		if h == hash {
			return true
		}
	}
	return false
}

// ProofFor generates a merkle proof for a hash in this commitment
func (c *Commitment) ProofFor(hash [32]byte) (*merkle.Proof, error) {
	tree, err := merkle.NewTree(c.Hashes)
	if err != nil {
		return nil, err
	}

	return tree.GenerateProof(hash)
}

// InclusionProof contains everything needed to verify hash inclusion
type InclusionProof struct {
	Commitment *Commitment   `json:"commitment"`
	Proof      *merkle.Proof `json:"proof"`
}

// NewInclusionProof creates an inclusion proof for a hash
func (c *Commitment) NewInclusionProof(hash [32]byte) (*InclusionProof, error) {
	proof, err := c.ProofFor(hash)
	if err != nil {
		return nil, err
	}

	return &InclusionProof{
		Commitment: c,
		Proof:      proof,
	}, nil
}

// Verify checks that the inclusion proof is valid
func (p *InclusionProof) Verify() error {
	// Verify commitment itself
	if err := p.Commitment.Verify(); err != nil {
		return err
	}

	// Verify merkle proof against commitment root
	return p.Proof.Verify(p.Commitment.Root)
}

// MarshalJSON implements custom JSON marshaling
func (c *Commitment) MarshalJSON() ([]byte, error) {
	type Alias Commitment
	return json.Marshal(&struct {
		Root   string   `json:"root"`
		Hashes []string `json:"hashes"`
		*Alias
	}{
		Root:   hexEncode(c.Root[:]),
		Hashes: hashesToHex(c.Hashes),
		Alias:  (*Alias)(c),
	})
}

// Helper functions
func hexEncode(b []byte) string {
	const hex = "0123456789abcdef"
	result := make([]byte, len(b)*2)
	for i, v := range b {
		result[i*2] = hex[v>>4]
		result[i*2+1] = hex[v&0x0f]
	}
	return string(result)
}

func hashesToHex(hashes [][32]byte) []string {
	result := make([]string, len(hashes))
	for i, h := range hashes {
		result[i] = hexEncode(h[:])
	}
	return result
}
