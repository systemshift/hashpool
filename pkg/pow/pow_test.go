package pow

import (
	"crypto/sha256"
	"testing"
)

func TestSolveAndVerify(t *testing.T) {
	hash := sha256.Sum256([]byte("test data"))

	tests := []struct {
		name       string
		difficulty uint8
	}{
		{"difficulty 8", 8},
		{"difficulty 12", 12},
		{"difficulty 16", 16},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			challenge := Solve(hash, tt.difficulty)

			if err := challenge.Verify(); err != nil {
				t.Errorf("Verify() error = %v", err)
			}

			if challenge.Hash != hash {
				t.Errorf("Hash mismatch")
			}

			if challenge.Difficulty != tt.difficulty {
				t.Errorf("Difficulty mismatch")
			}
		})
	}
}

func TestVerifyInvalid(t *testing.T) {
	hash := sha256.Sum256([]byte("test data"))

	challenge := Challenge{
		Hash:       hash,
		Nonce:      12345, // Unlikely to be valid
		Difficulty: 20,
	}

	if err := challenge.Verify(); err != ErrInvalidPoW {
		t.Errorf("Expected ErrInvalidPoW, got %v", err)
	}
}

func TestVerifyZeroDifficulty(t *testing.T) {
	challenge := Challenge{
		Hash:       sha256.Sum256([]byte("test")),
		Nonce:      0,
		Difficulty: 0,
	}

	if err := challenge.Verify(); err != ErrDifficultyZero {
		t.Errorf("Expected ErrDifficultyZero, got %v", err)
	}
}

func TestHasLeadingZeros(t *testing.T) {
	tests := []struct {
		hash     [32]byte
		zeros    uint8
		expected bool
	}{
		{[32]byte{0x00, 0x00, 0xFF}, 16, true},
		{[32]byte{0x00, 0x00, 0xFF}, 17, false},
		{[32]byte{0x00, 0x0F, 0xFF}, 12, true},
		{[32]byte{0x00, 0x0F, 0xFF}, 13, false},
		{[32]byte{0x00, 0x00, 0x00}, 24, true},
	}

	for _, tt := range tests {
		result := hasLeadingZeros(tt.hash, tt.zeros)
		if result != tt.expected {
			t.Errorf("hasLeadingZeros(%x, %d) = %v, want %v",
				tt.hash[:4], tt.zeros, result, tt.expected)
		}
	}
}

func BenchmarkSolve(b *testing.B) {
	hash := sha256.Sum256([]byte("benchmark data"))

	benchmarks := []struct {
		name       string
		difficulty uint8
	}{
		{"difficulty 8", 8},
		{"difficulty 12", 12},
		{"difficulty 16", 16},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				Solve(hash, bm.difficulty)
			}
		})
	}
}
