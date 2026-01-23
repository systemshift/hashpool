package mempool

import (
	"crypto/sha256"
	"sync"
	"testing"
	"time"

	"github.com/systemshift/hashpool/pkg/pow"
)

func TestSubmit(t *testing.T) {
	mp := New(Config{Difficulty: 8})
	defer mp.Close()

	hash := sha256.Sum256([]byte("test data"))
	challenge := pow.Solve(hash, 8)

	err := mp.Submit(hash, challenge.Nonce)
	if err != nil {
		t.Errorf("Submit() error = %v", err)
	}

	// Check it's in the mempool
	if mp.Count() != 1 {
		t.Errorf("Expected count 1, got %d", mp.Count())
	}
}

func TestSubmitDuplicate(t *testing.T) {
	mp := New(Config{Difficulty: 8})
	defer mp.Close()

	hash := sha256.Sum256([]byte("test data"))
	challenge := pow.Solve(hash, 8)

	_ = mp.Submit(hash, challenge.Nonce)
	err := mp.Submit(hash, challenge.Nonce)

	if err != ErrDuplicateHash {
		t.Errorf("Expected ErrDuplicateHash, got %v", err)
	}
}

func TestSubmitInvalidPoW(t *testing.T) {
	mp := New(Config{Difficulty: 16})
	defer mp.Close()

	hash := sha256.Sum256([]byte("test data"))

	err := mp.Submit(hash, 12345) // Unlikely to be valid
	if err == nil {
		t.Error("Expected error for invalid PoW")
	}
	// Should be pow.ErrInvalidPoW
	if err != pow.ErrInvalidPoW {
		t.Errorf("Expected pow.ErrInvalidPoW, got %v", err)
	}
}

func TestFlush(t *testing.T) {
	mp := New(Config{Difficulty: 8})
	defer mp.Close()

	// Add several hashes
	for i := 0; i < 5; i++ {
		hash := sha256.Sum256([]byte{byte(i)})
		challenge := pow.Solve(hash, 8)
		_ = mp.Submit(hash, challenge.Nonce)
	}

	if mp.Count() != 5 {
		t.Errorf("Expected count 5, got %d", mp.Count())
	}

	// Flush
	submissions := mp.Flush()
	if len(submissions) != 5 {
		t.Errorf("Expected 5 submissions, got %d", len(submissions))
	}

	// Mempool should be empty
	if mp.Count() != 0 {
		t.Errorf("Expected count 0 after flush, got %d", mp.Count())
	}
}

func TestConcurrentSubmit(t *testing.T) {
	mp := New(Config{Difficulty: 8})
	defer mp.Close()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			hash := sha256.Sum256([]byte{byte(n)})
			challenge := pow.Solve(hash, 8)
			_ = mp.Submit(hash, challenge.Nonce)
		}(i)
	}

	wg.Wait()

	// Should have all unique hashes (assuming no collisions in sha256 for 0-99)
	if mp.Count() != 100 {
		t.Errorf("Expected count 100, got %d", mp.Count())
	}
}

func TestOnSubmitCallback(t *testing.T) {
	mp := New(Config{Difficulty: 8})
	defer mp.Close()

	received := make(chan *Submission, 1)
	mp.SetOnSubmit(func(sub *Submission) {
		received <- sub
	})

	hash := sha256.Sum256([]byte("callback test"))
	challenge := pow.Solve(hash, 8)
	_ = mp.Submit(hash, challenge.Nonce)

	select {
	case sub := <-received:
		if sub.Hash != hash {
			t.Error("Callback received wrong hash")
		}
	case <-time.After(time.Second):
		t.Error("Callback not called within timeout")
	}
}

func TestSubmitFromPeer(t *testing.T) {
	mp := New(Config{Difficulty: 8})
	defer mp.Close()

	var callbackCalled bool
	mp.SetOnSubmit(func(sub *Submission) {
		callbackCalled = true
	})

	hash := sha256.Sum256([]byte("peer data"))
	challenge := pow.Solve(hash, 8)

	// Submit from peer should not trigger callback
	err := mp.SubmitFromPeer(hash, challenge.Nonce)
	if err != nil {
		t.Errorf("SubmitFromPeer() error = %v", err)
	}

	if callbackCalled {
		t.Error("Callback should not be called for peer submissions")
	}
}

func TestContains(t *testing.T) {
	mp := New(Config{Difficulty: 8})
	defer mp.Close()

	hash := sha256.Sum256([]byte("test"))
	challenge := pow.Solve(hash, 8)

	if mp.Contains(hash) {
		t.Error("Should not contain hash before submit")
	}

	_ = mp.Submit(hash, challenge.Nonce)

	if !mp.Contains(hash) {
		t.Error("Should contain hash after submit")
	}
}

func TestDifficulty(t *testing.T) {
	mp := New(Config{Difficulty: 12})
	defer mp.Close()

	if mp.Difficulty() != 12 {
		t.Errorf("Expected difficulty 12, got %d", mp.Difficulty())
	}

	mp.SetDifficulty(20)

	if mp.Difficulty() != 20 {
		t.Errorf("Expected difficulty 20, got %d", mp.Difficulty())
	}
}

func TestClosedMempool(t *testing.T) {
	mp := New(Config{Difficulty: 8})
	mp.Close()

	hash := sha256.Sum256([]byte("test"))
	challenge := pow.Solve(hash, 8)

	err := mp.Submit(hash, challenge.Nonce)
	if err != ErrPoolClosed {
		t.Errorf("Expected ErrPoolClosed, got %v", err)
	}
}
