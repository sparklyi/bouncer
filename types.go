package bouncer

import (
	"encoding/json"
	"log/slog"
	"time"
)

// Tier selects the verification layer for a challenge.
type Tier uint8

const (
	// TierPoW is the cost layer: a proof of work with escalating difficulty.
	TierPoW Tier = iota
	// TierSlide is the interaction layer: a slide challenge scored on the
	// pointer trajectory. It requires a Challenger registered for it.
	TierSlide
)

func (t Tier) String() string {
	switch t {
	case TierPoW:
		return "pow"
	case TierSlide:
		return "slide"
	default:
		return "unknown"
	}
}

// Escalate maps a failure count to a tier and a proof-of-work degree.
//
// The caller owns the failure count; the library does not store it. PoW
// difficulty is a latency budget for humans, not a economic wall for attackers:
// degrees above MaxDegree only hurt real users.
func Escalate(failures int) (Tier, uint8) {
	switch {
	case failures < 2:
		return TierPoW, 18
	case failures < 4:
		return TierPoW, 20
	case failures < 6:
		return TierPoW, 22
	default:
		return TierSlide, 24
	}
}

// Request describes the challenge to issue.
type Request struct {
	// Subject binds the ticket to a session or account. Optional.
	Subject string
	// Tier selects the challenge layer. The zero value is TierPoW.
	Tier Tier
	// Degree overrides the configured proof-of-work difficulty. Zero keeps
	// the configured default. Out-of-range values are clamped.
	Degree uint8
}

// Challenge is what the client receives. Params is challenge-specific public
// data; the answer to it never appears here.
type Challenge struct {
	ID      string
	Type    string
	Token   string
	Expires time.Time
	Params  json.RawMessage
}

// Solution is the client's answer to a claimed challenge. It is input only:
// never marshal it into a response.
type Solution struct {
	Token  string
	Answer string
}

// LogValue redacts the token and the answer so that logging a Solution cannot
// leak a usable ticket.
func (s Solution) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("token", "REDACTED"),
		slog.String("answer", "REDACTED"),
	)
}

// Verdict describes a successfully verified challenge.
type Verdict struct {
	Type     string
	Subject  string
	Degree   uint8
	IssuedAt time.Time
}

// PointerEvent is one sampled pointer position during an interaction. T is
// milliseconds since the interaction started.
type PointerEvent struct {
	X           int    `json:"x"`
	Y           int    `json:"y"`
	T           int64  `json:"t"`
	PointerType string `json:"pointer_type,omitempty"`
	Buttons     int    `json:"buttons,omitempty"`
}

// IssueInput is passed to a Challenger when a challenge is created.
type IssueInput struct {
	// Degree is the requested proof-of-work difficulty, already clamped.
	Degree uint8
}

// VerifyInput is passed to a Challenger when an answer is checked. State is the
// private state that was sealed into the ticket at issue time.
type VerifyInput struct {
	Params json.RawMessage
	State  []byte
	Answer string
}
