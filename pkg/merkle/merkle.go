// Package merkle implements a Merkle tree for hash commitments
package merkle

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"sort"
)

var (
	ErrEmptyHashes   = errors.New("cannot create merkle tree from empty hash list")
	ErrHashNotFound  = errors.New("hash not found in tree")
	ErrInvalidProof  = errors.New("invalid merkle proof")
)

// Proof represents a Merkle inclusion proof
type Proof struct {
	Hash     [32]byte   // The hash being proved
	Index    int        // Index in the sorted hash list
	Siblings [][32]byte // Sibling hashes from leaf to root
	Sides    []bool     // true = sibling is on right, false = left
}

// Tree represents a Merkle tree
type Tree struct {
	root   [32]byte
	leaves [][32]byte // sorted
	levels [][][32]byte
}

// NewTree creates a new Merkle tree from a list of hashes
// Hashes are sorted for deterministic ordering
func NewTree(hashes [][32]byte) (*Tree, error) {
	if len(hashes) == 0 {
		return nil, ErrEmptyHashes
	}

	// Sort hashes for deterministic ordering
	sorted := make([][32]byte, len(hashes))
	copy(sorted, hashes)
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(sorted[i][:], sorted[j][:]) < 0
	})

	t := &Tree{
		leaves: sorted,
	}

	t.build()
	return t, nil
}

// build constructs the Merkle tree from leaves to root
func (t *Tree) build() {
	t.levels = make([][][32]byte, 0)
	currentLevel := t.leaves

	for {
		t.levels = append(t.levels, currentLevel)

		if len(currentLevel) == 1 {
			t.root = currentLevel[0]
			return
		}

		nextLevel := make([][32]byte, 0, (len(currentLevel)+1)/2)

		for i := 0; i < len(currentLevel); i += 2 {
			if i+1 < len(currentLevel) {
				// Hash pair
				nextLevel = append(nextLevel, hashPair(currentLevel[i], currentLevel[i+1]))
			} else {
				// Odd element, promote it
				nextLevel = append(nextLevel, currentLevel[i])
			}
		}

		currentLevel = nextLevel
	}
}

// hashPair hashes two nodes together (left || right)
func hashPair(left, right [32]byte) [32]byte {
	var combined [64]byte
	copy(combined[:32], left[:])
	copy(combined[32:], right[:])
	return sha256.Sum256(combined[:])
}

// Root returns the Merkle root
func (t *Tree) Root() [32]byte {
	return t.root
}

// Leaves returns the sorted leaf hashes
func (t *Tree) Leaves() [][32]byte {
	return t.leaves
}

// GenerateProof creates an inclusion proof for a hash
func (t *Tree) GenerateProof(hash [32]byte) (*Proof, error) {
	// Find hash index in sorted leaves
	index := sort.Search(len(t.leaves), func(i int) bool {
		return bytes.Compare(t.leaves[i][:], hash[:]) >= 0
	})

	if index >= len(t.leaves) || t.leaves[index] != hash {
		return nil, ErrHashNotFound
	}

	proof := &Proof{
		Hash:     hash,
		Index:    index,
		Siblings: make([][32]byte, 0),
		Sides:    make([]bool, 0),
	}

	idx := index
	for level := 0; level < len(t.levels)-1; level++ {
		levelHashes := t.levels[level]

		if idx%2 == 0 {
			// We're on the left, sibling is on right
			if idx+1 < len(levelHashes) {
				proof.Siblings = append(proof.Siblings, levelHashes[idx+1])
				proof.Sides = append(proof.Sides, true) // sibling on right
			}
		} else {
			// We're on the right, sibling is on left
			proof.Siblings = append(proof.Siblings, levelHashes[idx-1])
			proof.Sides = append(proof.Sides, false) // sibling on left
		}

		idx = idx / 2
	}

	return proof, nil
}

// Verify checks if the proof is valid for the given root
func (p *Proof) Verify(root [32]byte) error {
	current := p.Hash

	for i, sibling := range p.Siblings {
		if p.Sides[i] {
			// Sibling on right
			current = hashPair(current, sibling)
		} else {
			// Sibling on left
			current = hashPair(sibling, current)
		}
	}

	if current != root {
		return ErrInvalidProof
	}

	return nil
}

// ComputeRoot is a convenience function to compute root from hashes
func ComputeRoot(hashes [][32]byte) ([32]byte, error) {
	tree, err := NewTree(hashes)
	if err != nil {
		return [32]byte{}, err
	}
	return tree.Root(), nil
}
