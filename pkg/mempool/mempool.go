// Package mempool implements a hash collection pool with PoW verification
package mempool

import (
	"errors"
	"sync"
	"time"

	"github.com/systemshift/hashpool/pkg/pow"
)

var (
	ErrPoolClosed    = errors.New("mempool is closed")
	ErrDuplicateHash = errors.New("hash already in pool")
)

// Submission represents a hash submission with its PoW
type Submission struct {
	Hash      [32]byte
	Nonce     uint64
	Timestamp time.Time
}

// Mempool collects hash submissions with PoW verification
type Mempool struct {
	mu         sync.RWMutex
	hashes     map[[32]byte]*Submission
	difficulty uint8
	closed     bool

	// Callbacks
	onSubmit func(*Submission) // Called when a valid submission is added
}

// Config holds mempool configuration
type Config struct {
	Difficulty uint8 // Required PoW difficulty (leading zero bits)
}

// New creates a new mempool with the given configuration
func New(cfg Config) *Mempool {
	if cfg.Difficulty == 0 {
		cfg.Difficulty = 16 // Default: ~65k hashes, ~0.1 sec on modern CPU
	}

	return &Mempool{
		hashes:     make(map[[32]byte]*Submission),
		difficulty: cfg.Difficulty,
	}
}

// SetOnSubmit sets a callback for when valid submissions are added
func (m *Mempool) SetOnSubmit(fn func(*Submission)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onSubmit = fn
}

// Submit adds a hash to the mempool after verifying PoW
func (m *Mempool) Submit(hash [32]byte, nonce uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrPoolClosed
	}

	// Check for duplicate
	if _, exists := m.hashes[hash]; exists {
		return ErrDuplicateHash
	}

	// Verify PoW
	challenge := pow.Challenge{
		Hash:       hash,
		Nonce:      nonce,
		Difficulty: m.difficulty,
	}
	if err := challenge.Verify(); err != nil {
		return err
	}

	// Add to pool
	sub := &Submission{
		Hash:      hash,
		Nonce:     nonce,
		Timestamp: time.Now(),
	}
	m.hashes[hash] = sub

	// Notify callback
	if m.onSubmit != nil {
		go m.onSubmit(sub)
	}

	return nil
}

// SubmitFromPeer adds a hash from a peer (already verified by them)
// Still verifies PoW but doesn't trigger onSubmit callback
func (m *Mempool) SubmitFromPeer(hash [32]byte, nonce uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return ErrPoolClosed
	}

	// Check for duplicate
	if _, exists := m.hashes[hash]; exists {
		return ErrDuplicateHash
	}

	// Verify PoW
	challenge := pow.Challenge{
		Hash:       hash,
		Nonce:      nonce,
		Difficulty: m.difficulty,
	}
	if err := challenge.Verify(); err != nil {
		return err
	}

	// Add to pool
	m.hashes[hash] = &Submission{
		Hash:      hash,
		Nonce:     nonce,
		Timestamp: time.Now(),
	}

	return nil
}

// Flush returns all hashes and clears the mempool
func (m *Mempool) Flush() []*Submission {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.hashes) == 0 {
		return nil
	}

	submissions := make([]*Submission, 0, len(m.hashes))
	for _, sub := range m.hashes {
		submissions = append(submissions, sub)
	}

	// Clear the pool
	m.hashes = make(map[[32]byte]*Submission)

	return submissions
}

// Count returns the number of hashes in the pool
func (m *Mempool) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.hashes)
}

// Contains checks if a hash is in the pool
func (m *Mempool) Contains(hash [32]byte) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.hashes[hash]
	return exists
}

// Difficulty returns the current PoW difficulty
func (m *Mempool) Difficulty() uint8 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.difficulty
}

// SetDifficulty updates the PoW difficulty
func (m *Mempool) SetDifficulty(d uint8) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.difficulty = d
}

// Close closes the mempool
func (m *Mempool) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}
