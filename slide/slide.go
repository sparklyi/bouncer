// Package slide implements the interaction layer: a puzzle piece that has to
// be dragged into a notch, validated server-side on the pointer trajectory.
//
// The notch is visible in the image, so the target position is recoverable by
// anyone who renders the canvas. The target x is therefore sealed into the
// ticket to defeat scripts, but the real decision boundary is the trajectory:
// template matching and one-shot coordinate injection are cheap, human-like
// motion is not.
package slide

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"image"
	"image/png"

	"github.com/sparklyi/bouncer"
)

const (
	// Type is the challenge identifier sent to clients.
	Type = "slide/v1"

	defaultWidth  = 320
	defaultHeight = 200
	defaultPiece  = 56
	defaultTol    = 8
	defaultMax    = 3
)

// ErrUntrusted reports a trajectory that is not plausible for a human.
var ErrUntrusted = errors.New("slide: untrusted trajectory")

// Params is the public challenge payload. It deliberately has no target x.
type Params struct {
	Image  string `json:"image"`
	Tile   string `json:"tile"`
	Y      int    `json:"y"`
	Piece  int    `json:"piece"`
	Tol    int    `json:"tol"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
}

type answer struct {
	X      int                    `json:"x"`
	Events []bouncer.PointerEvent `json:"events"`
}

// Challenge is a bouncer.Challenger for sliding puzzles.
type Challenge struct {
	width    int
	height   int
	piece    int
	tol      int
	maxTries int32
}

// Option configures a Challenge.
type Option func(*Challenge)

// WithSize sets the rendered canvas size.
func WithSize(w, h int) Option {
	return func(c *Challenge) {
		if w >= 200 && h >= 120 {
			c.width, c.height = w, h
		}
	}
}

// WithPiece sets the piece edge length in pixels.
func WithPiece(n int) Option {
	return func(c *Challenge) {
		if n >= 32 {
			c.piece = n
		}
	}
}

// WithTolerance sets the accepted horizontal error in pixels. Keep it
// generous: strictness here only punishes humans.
func WithTolerance(n int) Option {
	return func(c *Challenge) {
		if n > 0 {
			c.tol = n
		}
	}
}

// WithMaxAttempts sets how many answers one ticket accepts.
func WithMaxAttempts(n int32) Option {
	return func(c *Challenge) {
		if n > 0 {
			c.maxTries = n
		}
	}
}

// New returns a slide challenge with sensible defaults.
func New(opts ...Option) *Challenge {
	c := &Challenge{width: defaultWidth, height: defaultHeight, piece: defaultPiece, tol: defaultTol, maxTries: defaultMax}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	if c.tol < 4 {
		c.tol = 4
	}
	if tol := c.piece * 8 / 100; tol > c.tol {
		c.tol = tol
	}
	return c
}

// Tier reports the interaction layer.
func (*Challenge) Tier() bouncer.Tier { return bouncer.TierSlide }

// Type reports the challenge identifier.
func (*Challenge) Type() string { return Type }

// MaxAttempts bounds how many answers one ticket accepts.
func (c *Challenge) MaxAttempts() int32 { return c.maxTries }

// Issue renders a background, cuts a notch and returns public params plus the
// sealed state (target x, y, piece size and tolerance).
func (c *Challenge) Issue(_ context.Context, _ bouncer.IssueInput) ([]byte, []byte, error) {
	var seed [8]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, nil, err
	}
	scene := renderScene(seed, c.width, c.height, c.piece)

	params := Params{
		Image:  base64.StdEncoding.EncodeToString(scene.background),
		Tile:   base64.StdEncoding.EncodeToString(scene.tile),
		Y:      scene.y,
		Piece:  c.piece,
		Tol:    c.tol,
		Width:  c.width,
		Height: c.height,
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return nil, nil, err
	}
	state := make([]byte, 0, 6)
	state = binary.BigEndian.AppendUint16(state, uint16(scene.x))
	state = binary.BigEndian.AppendUint16(state, uint16(scene.y))
	state = append(state, byte(c.piece), byte(scene.tol))
	return raw, state, nil
}

// Verify checks the target position first and the trajectory second.
func (c *Challenge) Verify(_ context.Context, in bouncer.VerifyInput) error {
	if len(in.State) != 6 {
		return bouncer.ErrWrongAnswer
	}
	targetX := int(binary.BigEndian.Uint16(in.State[0:2]))
	piece := int(in.State[4])
	tol := int(in.State[5])

	var a answer
	if err := json.Unmarshal([]byte(in.Answer), &a); err != nil {
		return bouncer.ErrWrongAnswer
	}
	if abs(a.X-targetX) > tol {
		return bouncer.ErrWrongAnswer
	}
	if !trustedTrajectory(a.Events, c.width, c.height, piece, tol) {
		return ErrUntrusted
	}
	return nil
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func encodePNG(img image.Image) ([]byte, error) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
