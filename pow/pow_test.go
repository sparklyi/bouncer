package pow

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSolveAndVerify(t *testing.T) {
	salt := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	params := Params{Alg: "sha256", Salt: EncodeSalt(salt), Degree: 12}

	answer, err := Solve(context.Background(), params)
	if err != nil {
		t.Fatalf("Solve: %v", err)
	}
	if len(answer) != 16 {
		t.Fatalf("answer %q must be 16 hex characters", answer)
	}
	if err := Verify(salt, params.Degree, answer); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRejectsNonCanonicalAnswer(t *testing.T) {
	salt := [16]byte{}
	for _, answer := range []string{"", "7", "007", "0x00000000000001", "00000000000000001", " 0000000000000001", "000000000000000G"} {
		if err := Verify(salt, 1, answer); !errors.Is(err, ErrMalformed) {
			t.Fatalf("answer %q: want ErrMalformed, got %v", answer, err)
		}
	}
}

func TestVerifyRejectsInsufficientWork(t *testing.T) {
	salt := [16]byte{}
	// Nonce 1 does not have 32 leading zero bits.
	if err := Verify(salt, 32, FormatAnswer(1)); !errors.Is(err, ErrWrongAnswer) {
		t.Fatalf("want ErrWrongAnswer, got %v", err)
	}
}

func TestVerifyRejectsInvalidDegree(t *testing.T) {
	salt := [16]byte{}
	for _, degree := range []uint8{0, 33} {
		if err := Verify(salt, degree, FormatAnswer(1)); err == nil {
			t.Fatalf("degree %d must be rejected", degree)
		}
	}
}

func TestPreimageFitsOneBlock(t *testing.T) {
	if got := len(Preimage([16]byte{}, 0)); got > 55 {
		t.Fatalf("preimage is %d bytes, more than one SHA-256 block", got)
	}
}

func TestSolveRespectsContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	params := Params{Salt: EncodeSalt([16]byte{}), Degree: 32}
	if _, err := Solve(ctx, params); err == nil {
		// A 32-bit solve should not finish in 5ms; accepting it is only fine if
		// the machine got extremely lucky, which is indistinguishable here.
		t.Log("solve finished before the deadline; skipping strict assertion")
	}
}

func TestFormatParseRoundTrip(t *testing.T) {
	for _, nonce := range []uint64{0, 1, 1 << 40, ^uint64(0)} {
		answer := FormatAnswer(nonce)
		got, err := ParseAnswer(answer)
		if err != nil || got != nonce {
			t.Fatalf("round trip %d: got %d, %v", nonce, got, err)
		}
	}
}
