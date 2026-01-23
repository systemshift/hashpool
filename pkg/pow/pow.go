// Package pow implements hashcash-style proof of work for rate limiting
package pow

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
)

var (
	ErrInvalidPoW     = errors.New("invalid proof of work")
	ErrDifficultyZero = errors.New("difficulty cannot be zero")
)

// Challenge represents a proof of work challenge and solution
type Challenge struct {
	Hash       [32]byte // The hash being submitted
	Nonce      uint64   // The solution nonce
	Difficulty uint8    // Required leading zero bits
}

// Solve finds a nonce that satisfies the PoW requirement
// Returns the solved challenge
func Solve(hash [32]byte, difficulty uint8) Challenge {
	c := Challenge{
		Hash:       hash,
		Difficulty: difficulty,
	}

	for nonce := uint64(0); nonce < math.MaxUint64; nonce++ {
		c.Nonce = nonce
		if c.verify() {
			return c
		}
	}

	return c // Should never reach here with reasonable difficulty
}

// Verify checks if the challenge has a valid PoW solution
func (c *Challenge) Verify() error {
	if c.Difficulty == 0 {
		return ErrDifficultyZero
	}
	if !c.verify() {
		return ErrInvalidPoW
	}
	return nil
}

// verify is the internal verification without error handling
func (c *Challenge) verify() bool {
	hash := c.computeHash()
	return hasLeadingZeros(hash, c.Difficulty)
}

// computeHash computes SHA256(hash || nonce)
func (c *Challenge) computeHash() [32]byte {
	var buf [40]byte // 32 bytes hash + 8 bytes nonce
	copy(buf[:32], c.Hash[:])
	binary.BigEndian.PutUint64(buf[32:], c.Nonce)
	return sha256.Sum256(buf[:])
}

// hasLeadingZeros checks if hash has at least n leading zero bits
func hasLeadingZeros(hash [32]byte, n uint8) bool {
	fullBytes := n / 8
	remainingBits := n % 8

	// Check full zero bytes
	for i := uint8(0); i < fullBytes; i++ {
		if hash[i] != 0 {
			return false
		}
	}

	// Check remaining bits
	if remainingBits > 0 && fullBytes < 32 {
		mask := byte(0xFF) << (8 - remainingBits)
		if hash[fullBytes]&mask != 0 {
			return false
		}
	}

	return true
}

// EstimateSolveTime returns estimated solve time for given difficulty
// Based on expected number of hashes: 2^difficulty
func EstimateSolveTime(difficulty uint8, hashesPerSecond float64) float64 {
	expectedHashes := math.Pow(2, float64(difficulty))
	return expectedHashes / hashesPerSecond
}
