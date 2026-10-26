// Package pow implements the proof-of-work primitives used by bouncer.
//
// The construction is deliberately boring: one SHA-256 over a fixed 37-byte
// preimage, counting leading zero bits. Verification costs the server a single
// hash; the client pays 2^degree hashes.
//
// It is a rate limiter, not an economic wall. A 20-bit challenge costs a
// current GPU about 50 microseconds.
package pow

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
)

// Tag is the domain separator and algorithm identifier. It is part of the
// hashed preimage so that a future algorithm cannot satisfy this one.
const Tag = "bouncer/pow/v1"

// ErrWrongAnswer reports an answer that does not meet the difficulty.
var ErrWrongAnswer = errors.New("pow: wrong answer")

// ErrMalformed reports an answer that is not 16 lowercase hex characters.
var ErrMalformed = errors.New("pow: malformed answer")

// Params is the public challenge payload sent to the client.
type Params struct {
	Alg    string `json:"alg"`
	Salt   string `json:"salt"`
	Degree uint8  `json:"degree"`
}

// Preimage returns the exact 37-byte input that is hashed. Both sides must use
// this function; do not rebuild it by concatenating strings.
func Preimage(salt [16]byte, nonce uint64) []byte {
	out := make([]byte, 0, len(Tag)+16+8)
	out = append(out, Tag...)
	out = append(out, salt[:]...)
	return binary.BigEndian.AppendUint64(out, nonce)
}

// Hash returns the SHA-256 digest for a nonce.
func Hash(salt [16]byte, nonce uint64) [32]byte {
	return sha256.Sum256(Preimage(salt, nonce))
}

// Verify checks that answer is the canonical encoding of a nonce whose digest
// has at least degree leading zero bits.
func Verify(salt [16]byte, degree uint8, answer string) error {
	nonce, err := ParseAnswer(answer)
	if err != nil {
		return err
	}
	if degree == 0 || degree > 32 {
		return fmt.Errorf("pow: invalid degree %d", degree)
	}
	digest := Hash(salt, nonce)
	if leadingZeroBits(digest) < int(degree) {
		return ErrWrongAnswer
	}
	return nil
}

// ParseAnswer decodes the canonical 16 lowercase hex character encoding.
func ParseAnswer(answer string) (uint64, error) {
	if len(answer) != 16 {
		return 0, ErrMalformed
	}
	raw, err := hex.DecodeString(answer)
	if err != nil || hex.EncodeToString(raw) != answer {
		return 0, ErrMalformed
	}
	return binary.BigEndian.Uint64(raw), nil
}

// FormatAnswer encodes a nonce as the canonical 16 lowercase hex characters.
func FormatAnswer(nonce uint64) string {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], nonce)
	return hex.EncodeToString(raw[:])
}

// Solve finds an answer for params. It exists for Go clients, tests and
// benchmarks; browsers use the shipped worker instead.
func Solve(ctx context.Context, params Params) (string, error) {
	salt, err := decodeSalt(params.Salt)
	if err != nil {
		return "", err
	}
	if params.Degree == 0 || params.Degree > 32 {
		return "", fmt.Errorf("pow: invalid degree %d", params.Degree)
	}
	for nonce := uint64(1); ; nonce++ {
		if nonce%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return "", err
			}
		}
		if leadingZeroBits(Hash(salt, nonce)) >= int(params.Degree) {
			return FormatAnswer(nonce), nil
		}
	}
}

// EncodeSalt renders a salt for Params.
func EncodeSalt(salt [16]byte) string {
	return hex.EncodeToString(salt[:])
}

func decodeSalt(s string) ([16]byte, error) {
	var salt [16]byte
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != len(salt) {
		return salt, fmt.Errorf("pow: invalid salt")
	}
	copy(salt[:], raw)
	return salt, nil
}

func leadingZeroBits(digest [32]byte) int {
	n := 0
	for _, b := range digest {
		if b == 0 {
			n += 8
			continue
		}
		n += bits.LeadingZeros8(b)
		return n
	}
	return n
}
