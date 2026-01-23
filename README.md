# Hashpool: P2P Hash Timestamping with Proof of Work

[![Go Reference](https://pkg.go.dev/badge/github.com/systemshift/hashpool.svg)](https://pkg.go.dev/github.com/systemshift/hashpool)
[![Go Version](https://img.shields.io/github/go-mod/go-version/systemshift/hashpool)](https://go.dev/doc/devel/release)
[![License](https://img.shields.io/github/license/systemshift/hashpool)](LICENSE)

## Overview

Hashpool is a P2P network for timestamping hashes using Merkle commitments. It provides a decentralized mempool where anyone can submit hashes (with proof-of-work for rate limiting), which are then batched into Merkle trees at regular intervals.

Key features:

- **Proof of Work rate limiting** - No tokens or payments, just hashcash-style PoW
- **Merkle tree commitments** - Efficient batch proofs for hash inclusion
- **P2P gossip network** - Submissions propagate via libp2p GossipSub
- **Deterministic roots** - Same hashes always produce the same Merkle root

## Installation

### As a Library

```bash
go get github.com/systemshift/hashpool
```

```go
import (
    "github.com/systemshift/hashpool/pkg/pow"
    "github.com/systemshift/hashpool/pkg/merkle"
    "github.com/systemshift/hashpool/pkg/mempool"
    "github.com/systemshift/hashpool/pkg/commitment"
    "github.com/systemshift/hashpool/pkg/node"
)
```

### As a CLI Tool

```bash
go install github.com/systemshift/hashpool/cmd/hashpool@latest
```

## Quick Start

### Run a Node

```bash
hashpool -port 9000 -difficulty 16 -interval 10s -verbose
```

### Connect to a Peer

```bash
hashpool -port 9001 -peer /ip4/127.0.0.1/tcp/9000/p2p/<peer-id> -verbose
```

### Submit a Hash (Client Mode)

```bash
# Submit raw data (will be hashed)
hashpool -submit "hello world" -difficulty 16

# Submit a file
hashpool -submit /path/to/file -difficulty 16

# Submit a hex hash directly
hashpool -submit "a948904f2f0f479b8f8564cbf12dac6b18b5c7b8da6ec9e91ee3a0f4f5a5e3c2" -difficulty 16
```

## Library Usage

### Proof of Work

```go
import "github.com/systemshift/hashpool/pkg/pow"

// Solve PoW for a hash
hash := sha256.Sum256([]byte("my data"))
challenge := pow.Solve(hash, 16) // 16 leading zero bits

// Verify PoW
if err := challenge.Verify(); err != nil {
    log.Fatal("invalid PoW")
}
```

### Merkle Trees

```go
import "github.com/systemshift/hashpool/pkg/merkle"

// Create tree from hashes
hashes := [][32]byte{hash1, hash2, hash3}
tree, _ := merkle.NewTree(hashes)

// Get root
root := tree.Root()

// Generate inclusion proof
proof, _ := tree.GenerateProof(hash1)

// Verify proof against root
err := proof.Verify(root)
```

### Mempool

```go
import "github.com/systemshift/hashpool/pkg/mempool"

mp := mempool.New(mempool.Config{
    Difficulty: 16,
})

// Submit hash with PoW
mp.Submit(hash, nonce)

// Flush all hashes
submissions := mp.Flush()
```

### Full Node

```go
import "github.com/systemshift/hashpool/pkg/node"

cfg := node.Config{
    ListenPort:    9000,
    Difficulty:    16,
    RoundInterval: 10 * time.Second,
    Verbose:       true,
}

n, _ := node.New(ctx, cfg)
n.SetOnCommitment(func(c *commitment.Commitment) {
    fmt.Printf("Round %d: %d hashes, root: %x\n",
        c.Round, len(c.Hashes), c.Root[:8])
})

n.Start(ctx)
defer n.Stop()

// Submit a hash
challenge := pow.Solve(hash, n.Difficulty())
n.Submit(hash, challenge.Nonce)
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Clients                                                    │
│  - Solve PoW locally                                        │
│  - Submit hash + nonce to any node                          │
└─────────────────────────────────────────────────────────────┘
                          ↓ submit
┌─────────────────────────────────────────────────────────────┐
│  Hashpool Network (libp2p GossipSub)                        │
│  - Nodes gossip submissions to peers                        │
│  - Each node maintains local mempool                        │
│  - Duplicate/invalid submissions rejected                   │
└─────────────────────────────────────────────────────────────┘
                          ↓ every interval
┌─────────────────────────────────────────────────────────────┐
│  Commitment                                                 │
│  - Flush mempool                                            │
│  - Build Merkle tree (sorted for determinism)               │
│  - Broadcast commitment with root + hashes                  │
└─────────────────────────────────────────────────────────────┘
```

## The Problem This Solves

### Decentralized Timestamping Without Money

Traditional timestamping services require either:
- Centralized authorities (notaries, TSAs)
- Blockchain transactions (fees, tokens)

Hashpool provides timestamping with:
- **No tokens** - PoW is the only cost
- **No central authority** - P2P network
- **Verifiable proofs** - Merkle inclusion proofs
- **Spam resistance** - PoW rate limits submissions

### Use Cases

1. **Proof of Existence** - Prove a document existed before a certain time
2. **Commit-Reveal Schemes** - Commit to a value before revealing it
3. **Audit Trails** - Timestamp events without blockchain fees
4. **Data Integrity** - Prove data hasn't changed since commitment

## CLI Reference

```
hashpool [options]

Node Mode (default):
  -port int        Listen port (0 for random)
  -peer string     Bootstrap peer multiaddr
  -difficulty int  PoW difficulty in bits (default 16)
  -interval dur    Round interval (default 10s)
  -verbose         Enable verbose logging

Client Mode:
  -submit string   Hash to submit (hex, file path, or raw data)
  -peer string     Node to submit to (optional)
  -difficulty int  PoW difficulty (default 16)
```

## How It Works

1. **Submission**: Client solves PoW for their hash and submits to any node
2. **Gossip**: Node validates PoW and gossips submission to peers
3. **Collection**: All nodes collect submissions in their mempool
4. **Commitment**: At each interval, nodes flush mempool and build Merkle tree
5. **Broadcast**: Commitment (root + hashes) is broadcast to network
6. **Proof**: Anyone can generate/verify inclusion proofs against the root

## Requirements

- Go 1.23+

## Related Projects

- [DAG-Time](https://github.com/systemshift/dag-time) - Temporal ordering with drand anchoring
- [Claim-Graph](https://github.com/systemshift/claim-graph) - Portable trust for decentralized systems

## License

BSD 3-Clause License. See [LICENSE](LICENSE) for details.
