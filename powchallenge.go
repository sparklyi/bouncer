package bouncer

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"

	"github.com/sparklyi/bouncer/pow"
)

const powType = "pow/sha256"

// powChallenge is the built-in cost layer. It needs no store: the answer is
// self-verifying, so a verification costs one SHA-256.
type powChallenge struct{}

func newPoWChallenge() *powChallenge { return &powChallenge{} }

func (*powChallenge) Tier() Tier   { return TierPoW }
func (*powChallenge) Type() string { return powType }

func (*powChallenge) Issue(_ context.Context, in IssueInput) ([]byte, []byte, error) {
	var salt [16]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, nil, errors.New("bouncer: salt: " + err.Error())
	}
	degree := clampDegree(in.Degree)
	params, err := json.Marshal(pow.Params{
		Alg:    "sha256",
		Salt:   pow.EncodeSalt(salt),
		Degree: degree,
	})
	if err != nil {
		return nil, nil, err
	}
	state := make([]byte, 0, len(salt)+1)
	state = append(state, salt[:]...)
	state = append(state, degree)
	return params, state, nil
}

func (*powChallenge) Verify(_ context.Context, in VerifyInput) error {
	if len(in.State) != 17 {
		return ErrWrongAnswer
	}
	var salt [16]byte
	copy(salt[:], in.State[:16])
	degree := in.State[16]
	if err := pow.Verify(salt, degree, in.Answer); err != nil {
		if errors.Is(err, pow.ErrWrongAnswer) || errors.Is(err, pow.ErrMalformed) {
			return ErrWrongAnswer
		}
		return err
	}
	return nil
}
