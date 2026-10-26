// Package bouncer issues and verifies single-use human-verification challenges.
//
// A challenge is sealed into an opaque ticket: the client can neither read nor
// modify the difficulty, the expiry, the subject binding, or any private
// challenge state. Verification decrypts the ticket, asks the challenge to
// check the submitted answer, and atomically consumes the ticket so that it
// cannot be redeemed twice.
//
// The package has no third-party dependencies. A single verification costs one
// SHA-256 hash for the built-in proof-of-work challenge; the work is done by the
// client.
//
//	g, err := bouncer.New(bouncer.WithSecret(key))
//	if err != nil {
//		return err
//	}
//	ch, err := g.Issue(ctx, bouncer.Request{})
//	// send ch.Token and ch.Params to the client
//	v, err := g.Verify(ctx, bouncer.Solution{Token: token, Answer: answer})
//
// bouncer proves that a client spent computational and interaction effort. It
// does not prove that the client is a human, and it is not a risk engine.
package bouncer
