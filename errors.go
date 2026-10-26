package bouncer

import "errors"

// Sentinel errors returned by Gate and its challenges. Test with errors.Is.
var (
	// ErrNoSecret reports a missing or too short master secret.
	ErrNoSecret = errors.New("bouncer: secret must be at least 32 bytes")
	// ErrMalformed reports a token that cannot be parsed.
	ErrMalformed = errors.New("bouncer: malformed token")
	// ErrBadToken reports a token whose authentication tag did not verify.
	ErrBadToken = errors.New("bouncer: token authentication failed")
	// ErrExpired reports a token past its expiry.
	ErrExpired = errors.New("bouncer: token expired")
	// ErrReplay reports a ticket that was already redeemed.
	ErrReplay = errors.New("bouncer: ticket already used")
	// ErrSubjectMismatch reports a ticket bound to a different subject.
	ErrSubjectMismatch = errors.New("bouncer: subject mismatch")
	// ErrWrongAnswer reports an answer that does not solve the challenge.
	ErrWrongAnswer = errors.New("bouncer: wrong answer")
	// ErrAttemptsExceeded reports an exhausted attempt budget.
	ErrAttemptsExceeded = errors.New("bouncer: attempt budget exhausted")
	// ErrUnsupportedType reports a challenge type this Gate cannot verify.
	ErrUnsupportedType = errors.New("bouncer: unsupported challenge type")
	// ErrStore reports a backing store failure.
	ErrStore = errors.New("bouncer: store failure")
	// ErrClosed reports use of a closed Gate.
	ErrClosed = errors.New("bouncer: gate is closed")
	// ErrCapacity reports a store that reached its entry cap.
	ErrCapacity = errors.New("bouncer: store capacity reached")
)

// Error adds the operation to a sentinel error while keeping errors.Is working.
type Error struct {
	Op  string
	Err error
}

func (e *Error) Error() string {
	if e.Op == "" {
		return e.Err.Error()
	}
	return "bouncer: " + e.Op + ": " + e.Err.Error()
}

func (e *Error) Unwrap() error { return e.Err }

func wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return err
	}
	return &Error{Op: op, Err: err}
}
