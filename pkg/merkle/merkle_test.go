package merkle

import (
	"crypto/sha256"
	"testing"
)

func TestNewTree(t *testing.T) {
	hashes := make([][32]byte, 5)
	for i := range hashes {
		hashes[i] = sha256.Sum256([]byte{byte(i)})
	}

	tree, err := NewTree(hashes)
	if err != nil {
		t.Fatalf("NewTree() error = %v", err)
	}

	// Root should not be zero
	var zero [32]byte
	if tree.Root() == zero {
		t.Error("Root is zero")
	}

	// Leaves should be sorted
	leaves := tree.Leaves()
	if len(leaves) != 5 {
		t.Errorf("Expected 5 leaves, got %d", len(leaves))
	}
}

func TestNewTreeEmpty(t *testing.T) {
	_, err := NewTree(nil)
	if err != ErrEmptyHashes {
		t.Errorf("Expected ErrEmptyHashes, got %v", err)
	}
}

func TestGenerateAndVerifyProof(t *testing.T) {
	hashes := make([][32]byte, 7)
	for i := range hashes {
		hashes[i] = sha256.Sum256([]byte{byte(i)})
	}

	tree, err := NewTree(hashes)
	if err != nil {
		t.Fatalf("NewTree() error = %v", err)
	}

	// Generate and verify proof for each hash
	for _, hash := range hashes {
		proof, err := tree.GenerateProof(hash)
		if err != nil {
			t.Errorf("GenerateProof() error = %v", err)
			continue
		}

		if err := proof.Verify(tree.Root()); err != nil {
			t.Errorf("Proof.Verify() error = %v", err)
		}
	}
}

func TestProofNotFound(t *testing.T) {
	hashes := make([][32]byte, 3)
	for i := range hashes {
		hashes[i] = sha256.Sum256([]byte{byte(i)})
	}

	tree, err := NewTree(hashes)
	if err != nil {
		t.Fatalf("NewTree() error = %v", err)
	}

	// Try to prove a hash not in the tree
	notInTree := sha256.Sum256([]byte{255})
	_, err = tree.GenerateProof(notInTree)
	if err != ErrHashNotFound {
		t.Errorf("Expected ErrHashNotFound, got %v", err)
	}
}

func TestProofInvalidRoot(t *testing.T) {
	hashes := make([][32]byte, 3)
	for i := range hashes {
		hashes[i] = sha256.Sum256([]byte{byte(i)})
	}

	tree, err := NewTree(hashes)
	if err != nil {
		t.Fatalf("NewTree() error = %v", err)
	}

	proof, err := tree.GenerateProof(hashes[0])
	if err != nil {
		t.Fatalf("GenerateProof() error = %v", err)
	}

	// Verify against wrong root
	wrongRoot := sha256.Sum256([]byte("wrong"))
	if err := proof.Verify(wrongRoot); err != ErrInvalidProof {
		t.Errorf("Expected ErrInvalidProof, got %v", err)
	}
}

func TestDeterministicRoot(t *testing.T) {
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

	tree1, _ := NewTree(hashes1)
	tree2, _ := NewTree(hashes2)

	if tree1.Root() != tree2.Root() {
		t.Error("Same hashes in different order should produce same root")
	}
}

func TestComputeRoot(t *testing.T) {
	hashes := make([][32]byte, 4)
	for i := range hashes {
		hashes[i] = sha256.Sum256([]byte{byte(i)})
	}

	root1, err := ComputeRoot(hashes)
	if err != nil {
		t.Fatalf("ComputeRoot() error = %v", err)
	}

	tree, _ := NewTree(hashes)
	root2 := tree.Root()

	if root1 != root2 {
		t.Error("ComputeRoot() and tree.Root() differ")
	}
}
