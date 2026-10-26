package bouncer_test

import (
	"bytes"
	"context"
	"fmt"

	"github.com/sparklyi/bouncer"
)

func ExampleGate_Issue() {
	key := bytes.Repeat([]byte("k"), 32)
	g, err := bouncer.New(bouncer.WithSecret(key))
	if err != nil {
		panic(err)
	}
	defer g.Close()

	challenge, err := g.Issue(context.Background(), bouncer.Request{})
	if err != nil {
		panic(err)
	}
	fmt.Println(challenge.Type)
	// Output: pow/sha256
}

func ExampleEscalate() {
	for _, failures := range []int{0, 3, 6} {
		tier, degree := bouncer.Escalate(failures)
		fmt.Printf("%d failures -> %s at %d bits\n", failures, tier, degree)
	}
	// Output:
	// 0 failures -> pow at 18 bits
	// 3 failures -> pow at 20 bits
	// 6 failures -> slide at 24 bits
}
