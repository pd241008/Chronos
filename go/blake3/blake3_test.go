package blake3

import (
	"chronosd/ringbuf"
	"testing"
)

// TestHashDeterminism ensures hashing the same input twice yields the same digest.
func TestHashDeterminism(t *testing.T) {
	input := []byte("the quick brown fox jumps over the lazy dog")
	a := Hash(input)
	b := Hash(input)
	if a != b {
		t.Errorf("Hash is not deterministic: %x != %x", a, b)
	}
}

// TestHashAvalanche ensures flipping one input bit changes the digest.
func TestHashAvalanche(t *testing.T) {
	base := []byte("hello world")
	h1 := Hash(base)
	modified := append([]byte(nil), base...)
	modified[0] ^= 0x01
	h2 := Hash(modified)
	if h1 == h2 {
		t.Error("Hash did not change when one input bit flipped")
	}
}

// TestHashEmpty ensures hashing empty input is stable.
func TestHashEmpty(t *testing.T) {
	a := Hash(nil)
	b := Hash([]byte{})
	if a != b {
		t.Errorf("Hash(nil) != Hash([]byte{}): %x != %x", a, b)
	}
}

// TestKeyedVsUnkeyed ensures keyed and unkeyed hashes differ.
func TestKeyedVsUnkeyed(t *testing.T) {
	input := []byte("some data")
	unkeyed := Hash(input)
	keyed := HashKeyed([]byte("secret-key-32bytes!!secret-key-32bytes!!"), input)
	if unkeyed == keyed {
		t.Error("Keyed and unkeyed hashes are identical, expected difference")
	}
}

// TestHasherIncremental ensures incremental Write matches one-shot Hash.
func TestHasherIncremental(t *testing.T) {
	input := []byte("incremental hashing test data")
	h := New()
	// Write in chunks
	third := len(input) / 3
	h.Write(input[:third])
	h.Write(input[third : 2*third])
	h.Write(input[2*third:])
	inc := h.Sum32()
	oneShot := Hash(input)
	if inc != oneShot {
		t.Errorf("incremental hash %x != one-shot hash %x", inc, oneShot)
	}
}

// TestDeriveKey ensures key derivation is deterministic.
func TestDeriveKey(t *testing.T) {
	ctx := []byte("chronos-context")
	in := []byte("extent-data")
	k1 := DeriveKey(ctx, in)
	k2 := DeriveKey(ctx, in)
	if k1 != k2 {
		t.Errorf("DeriveKey not deterministic: %x != %x", k1, k2)
	}
	if k1 == Hash(in) {
		t.Error("DeriveKey should differ from plain hash")
	}
}

// TestMerkleSingleLeaf ensures a single-leaf tree root equals the leaf digest.
func TestMerkleSingleLeaf(t *testing.T) {
	leaf := Hash([]byte("single extent pre-image"))
	tree := NewCommitmentTree()
	tree.AddLeafBytes(leaf)
	root := tree.Root()
	if root != leaf {
		t.Errorf("single-leaf Merkle root %x != leaf %x", root, leaf)
	}
}

// TestMerkleMultipleLeaves ensures multi-leaf root is deterministic and differs from leaves.
func TestMerkleMultipleLeaves(t *testing.T) {
	l1 := Hash([]byte("leaf one"))
	l2 := Hash([]byte("leaf two"))
	l3 := Hash([]byte("leaf three"))

	tree := NewCommitmentTree()
	tree.AddLeafBytes(l1)
	tree.AddLeafBytes(l2)
	tree.AddLeafBytes(l3)
	root := tree.Root()

	if root == l1 || root == l2 || root == l3 {
		t.Error("Merkle root equals a leaf digest, unexpected for multi-leaf tree")
	}

	// Determinism
	tree2 := NewCommitmentTree()
	tree2.AddLeafBytes(l1)
	tree2.AddLeafBytes(l2)
	tree2.AddLeafBytes(l3)
	if tree2.Root() != root {
		t.Error("Merkle root not deterministic")
	}
}

// TestMerkleAvalanche ensures changing one leaf changes the root.
func TestMerkleAvalanche(t *testing.T) {
	treeA := NewCommitmentTree()
	treeA.AddLeafBytes(Hash([]byte("alpha")))
	treeA.AddLeafBytes(Hash([]byte("beta")))
	rootA := treeA.Root()

	treeB := NewCommitmentTree()
	treeB.AddLeafBytes(Hash([]byte("alpha")))
	treeB.AddLeafBytes(Hash([]byte("beta-changed")))
	rootB := treeB.Root()

	if rootA == rootB {
		t.Error("Merkle root did not change when a leaf changed")
	}
}

// TestCommitAndVerifyExtent ensures Commit over descriptors then VerifyExtent self-consistency.
func TestCommitAndVerifyExtent(t *testing.T) {
	desc := &ringbuf.ExtentDesc{
		PID:  1234,
		Size: 16,
		Data: [65536]byte{},
	}
	copy(desc.Data[:], []byte("merkle-test-data"))

	root, err := Commit([]*ringbuf.ExtentDesc{desc})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	ok, err := VerifyExtent(desc, Hash(desc.Data[:int(desc.Size)]))
	if err != nil {
		t.Fatalf("VerifyExtent: %v", err)
	}
	if !ok {
		t.Error("VerifyExtent returned false for intact descriptor")
	}
	_ = root
}

// TestMerkleEngine ensures NewMerkle / AddExtent / Root / Commit works.
func TestMerkleEngine(t *testing.T) {
	m := NewMerkle()
	d1 := &ringbuf.ExtentDesc{PID: 1, Size: 5, Data: [65536]byte{}}
	copy(d1.Data[:], []byte("hello"))
	d2 := &ringbuf.ExtentDesc{PID: 2, Size: 5, Data: [65536]byte{}}
	copy(d2.Data[:], []byte("world"))

	m.AddExtent(d1)
	m.AddExtent(d2)
	root := m.Root()

	// Commit resets the tree
	root2, err := m.Commit()
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if root != root2 {
		t.Error("Root before Commit != Commit() result")
	}

	// After commit, tree is empty
	emptyRoot := m.Root()
	if emptyRoot == root {
		t.Error("Tree should be empty after Commit")
	}
	_ = root2
}

// ensure ExtentDesc is referenced
var _ = ringbuf.ExtentDesc{}
