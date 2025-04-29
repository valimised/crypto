package pet

import (
	"crypto/rand"
	"fmt"
	"io"
	"testing"

	"gitlab.com/tivi-io/crypto/group/nistec"
	"gitlab.com/tivi-io/crypto/hash"
	"gitlab.com/tivi-io/crypto/pok/commitment/pedersen"
	"gitlab.com/tivi-io/crypto/prng/dprng"
)

func ExampleProveVerifyWhenPlaintextInCiphertextAndCommitmentDiffer() {
	G := nistec.NewP384Group(nistec.Params{PointEncodingBits: 10})

	plain := []byte("0000.102")
	m := G.ZeroScalar() // plaintext as scalar
	_, err := m.SetBytes(plain)
	if err != nil {
		panic(err)
	}

	x := G.ZeroScalar()
	if _, err := x.SetReader(rand.Reader); err != nil { // private key
		panic(err)
	}

	r := G.ZeroScalar()
	if _, err := r.SetReader(rand.Reader); err != nil { // encryption randomness
		panic(err)
	}

	// Lifted ElGamal
	c1 := G.Identity()
	_, err = c1.GeneratorScale(r) // c1 = g^r
	if err != nil {
		panic(err)
	}
	xrm := G.ZeroScalar()
	if _, err := xrm.Add(r); err != nil { // r
		panic(err)
	}
	if _, err := xrm.Mul(x); err != nil { // rx
		panic(err)
	}
	if _, err := xrm.Add(m); err != nil { // rx + m
		panic(err)
	}
	c2 := G.Identity()
	if _, err = c2.GeneratorScale(xrm); err != nil { // c2 = g^(rx + m)
		panic(err)
	}
	one := G.ZeroScalar()
	if _, err := one.SetBytes([]byte{0x01}); err != nil {
		panic(err)
	}
	g := G.Identity()
	if _, err := g.GeneratorScale(one); err != nil { // g
		panic(err)
	}
	y := G.Identity()
	if _, err := y.GeneratorScale(x); err != nil { // public key = g^x
		panic(err)
	}

	// Pedersen commitment
	h := G.Identity()
	xx, err := x.SetReader(rand.Reader)
	if err != nil {
		panic(err)
	}

	if _, err := h.GeneratorScale(xx); err != nil { // Pedersen random generator h
		panic(err)
	}

	k := G.ZeroScalar()
	if _, err := k.SetReader(rand.Reader); err != nil { // Pedersen commitment randomness
		panic(err)
	}

	mm, err := G.ZeroScalar().SetBytes([]byte("0000.103")) // NB! We have encrypted 0000.102, but commit 0000.103
	if err != nil {
		panic(err)
	}
	com, err := pedersen.Commit(mm, k, &pedersen.CommitmentKey{Group: G, G: g, H: h}) // commitment = (g^m, h^k)
	if err != nil {
		panic(err)
	}

	// Proof that message in a ciphertext is the same as in a commitment
	opts := &CommitOpts{
		G:    G,
		PK:   y,
		H:    h,
		R:    r.Bytes(),
		R_:   k.Bytes(),
		M:    m.Bytes(),
		Prng: dprng.New(hash.SHA256),
	}
	commitment, respOpts, err := Commit(rand.Reader, opts)
	if err != nil {
		panic(err)
	}

	prngs := dprng.New(hash.SHA256)
	out := make([]byte, (G.OrderBitLen()+7)/8)
	err = Challenge(prngs, out, commitment)
	if err != nil {
		panic(err)
	}

	resp, err := Response(out, respOpts)
	if err != nil {
		panic(err)
	}

	opts2 := &VerifyOpts{
		G:  G,
		PK: y,
		H:  h,
		C1: c1,
		C2: c2,
		C3: com.Bytes(),
	}

	err = Verify(commitment, out, resp, opts2)

	fmt.Println(err)
	// Output:
	// invalid commitment d_3
}

func TestProveVerify(t *testing.T) {
	G := nistec.NewP384Group(nistec.Params{PointEncodingBits: 10})

	plain := []byte("0000.102")
	m := G.ZeroScalar() // plaintext as scalar
	_, err := m.SetBytes(plain)
	if err != nil {
		t.Fatal(err)
	}

	x := G.ZeroScalar()
	if _, err := x.SetReader(rand.Reader); err != nil { // private key
		t.Fatal(err)
	}

	r := G.ZeroScalar()
	if _, err := r.SetReader(rand.Reader); err != nil { // encryption randomness
		t.Fatal(err)
	}

	// Lifted ElGamal
	c1 := G.Identity()
	_, err = c1.GeneratorScale(r) // c1 = g^r
	if err != nil {
		t.Fatal(err)
	}
	xrm := G.ZeroScalar()
	if _, err := xrm.Add(r); err != nil { // r
		t.Fatal(err)
	}
	if _, err := xrm.Mul(x); err != nil { // rx
		t.Fatal(err)
	}
	if _, err := xrm.Add(m); err != nil { // rx + m
		t.Fatal(err)
	}
	c2 := G.Identity()
	if _, err = c2.GeneratorScale(xrm); err != nil { // c2 = g^(rx + m)
		t.Fatal(err)
	}
	one := G.ZeroScalar()
	if _, err := one.SetBytes([]byte{0x01}); err != nil {
		t.Fatal(err)
	}
	g := G.Identity()
	if _, err := g.GeneratorScale(one); err != nil { // g
		t.Fatal(err)
	}
	y := G.Identity()
	if _, err := y.GeneratorScale(x); err != nil { // public key = g^x
		t.Fatal(err)
	}

	// Pedersen commitment
	h := G.Identity()
	xx, err := x.SetReader(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.GeneratorScale(xx); err != nil { // Pedersen random generator h
		t.Fatal(err)
	}

	k := G.ZeroScalar()
	if _, err := k.SetReader(rand.Reader); err != nil { // Pedersen commitment randomness
		t.Fatal(err)
	}

	com, err := pedersen.Commit(m, k, &pedersen.CommitmentKey{Group: G, G: g, H: h}) // commitment = (g^m, h^k)
	if err != nil {
		t.Fatal(err)
	}

	// Prover --> Verifier
	opts := &CommitOpts{
		G:    G,
		PK:   y,
		H:    h,
		R:    r.Bytes(),
		R_:   k.Bytes(),
		M:    m.Bytes(),
		Prng: dprng.New(hash.SHA256),
	}
	commitment, respOpts, err := Commit(rand.Reader, opts)
	if err != nil {
		t.Fatal(err)
	}

	// Prover <-- Verifier (note that in case of non-interactive proof, this step is done on Prover side)
	prngs := dprng.New(hash.SHA256)
	out := make([]byte, (G.OrderBitLen()+7)/8)
	err = Challenge(prngs, out, commitment)
	if err != nil {
		t.Fatal(err)
	}

	// Prover --> Verifier
	resp, err := Response(out, respOpts)
	if err != nil {
		t.Fatal(err)
	}

	// Prover <-- Verifier (note that in case of non-interactive proof, Challenge is called on Verifier side as well
	// to generate a challenge out of provided Prover commitments)
	opts2 := &VerifyOpts{
		G:  G,
		PK: y,
		H:  h,
		C1: c1,
		C2: c2,
		C3: com.Bytes(),
	}
	if err = Verify(commitment, out, resp, opts2); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkCommit(b *testing.B) {
	G := nistec.NewP384Group(nistec.Params{PointEncodingBits: 10})

	plain := []byte("0000.102")
	m := G.ZeroScalar() // plaintext as scalar
	_, err := m.SetBytes(plain)
	if err != nil {
		b.Fatal(err)
	}

	x := G.ZeroScalar()
	if _, err := x.SetReader(rand.Reader); err != nil { // private key
		b.Fatal(err)
	}

	r := G.ZeroScalar()
	if _, err := r.SetReader(rand.Reader); err != nil { // encryption randomness
		b.Fatal(err)
	}

	// Lifted ElGamal
	c1 := G.Identity()
	_, err = c1.GeneratorScale(r) // c1 = g^r
	if err != nil {
		b.Fatal(err)
	}
	xrm := G.ZeroScalar()
	if _, err := xrm.Add(r); err != nil { // r
		b.Fatal(err)
	}
	if _, err := xrm.Mul(x); err != nil { // rx
		b.Fatal(err)
	}
	if _, err := xrm.Add(m); err != nil { // rx + m
		b.Fatal(err)
	}
	c2 := G.Identity()
	if _, err = c2.GeneratorScale(xrm); err != nil { // c2 = g^(rx + m)
		b.Fatal(err)
	}
	one := G.ZeroScalar()
	if _, err := one.SetBytes([]byte{0x01}); err != nil {
		b.Fatal(err)
	}
	g := G.Identity()
	if _, err := g.GeneratorScale(one); err != nil { // g
		b.Fatal(err)
	}
	y := G.Identity()
	if _, err := y.GeneratorScale(x); err != nil { // public key = g^x
		b.Fatal(err)
	}

	// Pedersen commitment
	h := G.Identity()
	xx, err := x.SetReader(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	if _, err := h.GeneratorScale(xx); err != nil { // Pedersen random generator h
		b.Fatal(err)
	}

	k := G.ZeroScalar()
	if _, err := k.SetReader(rand.Reader); err != nil { // Pedersen commitment randomness
		b.Fatal(err)
	}

	_, err = pedersen.Commit(m, k, &pedersen.CommitmentKey{Group: G, G: g, H: h}) // commitment = (g^m, h^k)
	if err != nil {
		b.Fatal(err)
	}

	// Proof that message in a ciphertext is the same as in a commitment
	opts := &CommitOpts{
		G:    G,
		PK:   y,
		H:    h,
		R:    r.Bytes(),
		R_:   k.Bytes(),
		M:    m.Bytes(),
		Prng: dprng.New(hash.SHA256),
	}
	var commitment []byte
	var respOpts *ResponseOpts

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		commitment, respOpts, err = Commit(rand.Reader, opts)
	}
	b.StopTimer()
	// 1259521 ns/op	1968 B/op	28 allocs/op

	fmt.Fprint(io.Discard, commitment, respOpts, err)
}

func TestCommitRegression(t *testing.T) {
	expected := 28.0

	G := nistec.NewP384Group(nistec.Params{PointEncodingBits: 10})

	plain := []byte("0000.102")
	m := G.ZeroScalar() // plaintext as scalar
	_, err := m.SetBytes(plain)
	if err != nil {
		t.Fatal(err)
	}

	x := G.ZeroScalar()
	if _, err := x.SetReader(rand.Reader); err != nil { // private key
		t.Fatal(err)
	}

	r := G.ZeroScalar()
	if _, err := r.SetReader(rand.Reader); err != nil { // encryption randomness
		t.Fatal(err)
	}

	// Lifted ElGamal
	c1 := G.Identity()
	_, err = c1.GeneratorScale(r) // c1 = g^r
	if err != nil {
		t.Fatal(err)
	}
	xrm := G.ZeroScalar()
	if _, err := xrm.Add(r); err != nil { // r
		t.Fatal(err)
	}
	if _, err := xrm.Mul(x); err != nil { // rx
		t.Fatal(err)
	}
	if _, err := xrm.Add(m); err != nil { // rx + m
		t.Fatal(err)
	}
	c2 := G.Identity()
	if _, err = c2.GeneratorScale(xrm); err != nil { // c2 = g^(rx + m)
		t.Fatal(err)
	}
	one := G.ZeroScalar()
	if _, err := one.SetBytes([]byte{0x01}); err != nil {
		t.Fatal(err)
	}
	g := G.Identity()
	if _, err := g.GeneratorScale(one); err != nil { // g
		t.Fatal(err)
	}
	y := G.Identity()
	if _, err := y.GeneratorScale(x); err != nil { // public key = g^x
		t.Fatal(err)
	}

	// Pedersen commitment
	h := G.Identity()
	xx, err := x.SetReader(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.GeneratorScale(xx); err != nil { // Pedersen random generator h
		t.Fatal(err)
	}

	k := G.ZeroScalar()
	if _, err := k.SetReader(rand.Reader); err != nil { // Pedersen commitment randomness
		t.Fatal(err)
	}

	_, err = pedersen.Commit(m, k, &pedersen.CommitmentKey{Group: G, G: g, H: h}) // commitment = (g^m, h^k)
	if err != nil {
		t.Fatal(err)
	}

	// Proof that message in a ciphertext is the same as in a commitment
	opts := &CommitOpts{
		G:    G,
		PK:   y,
		H:    h,
		R:    r.Bytes(),
		R_:   k.Bytes(),
		M:    m.Bytes(),
		Prng: dprng.New(hash.SHA256),
	}
	var commitment []byte
	var respOpts *ResponseOpts

	if allocs := testing.AllocsPerRun(10, func() {
		commitment, respOpts, err = Commit(rand.Reader, opts)
	}); allocs > expected {
		t.Fatalf("Commit now requires %0.f heap allocations, while before required %0.f", allocs, expected)
	}

	fmt.Fprint(io.Discard, commitment, respOpts, err)
}

func BenchmarkChallenge(b *testing.B) {
	G := nistec.NewP384Group(nistec.Params{PointEncodingBits: 10})

	plain := []byte("0000.102")
	m := G.ZeroScalar() // plaintext as scalar
	_, err := m.SetBytes(plain)
	if err != nil {
		b.Fatal(err)
	}

	x := G.ZeroScalar()
	if _, err := x.SetReader(rand.Reader); err != nil { // private key
		b.Fatal(err)
	}

	r := G.ZeroScalar()
	if _, err := r.SetReader(rand.Reader); err != nil { // encryption randomness
		b.Fatal(err)
	}

	// Lifted ElGamal
	c1 := G.Identity()
	_, err = c1.GeneratorScale(r) // c1 = g^r
	if err != nil {
		b.Fatal(err)
	}
	xrm := G.ZeroScalar()
	if _, err := xrm.Add(r); err != nil { // r
		b.Fatal(err)
	}
	if _, err := xrm.Mul(x); err != nil { // rx
		b.Fatal(err)
	}
	if _, err := xrm.Add(m); err != nil { // rx + m
		b.Fatal(err)
	}
	c2 := G.Identity()
	if _, err = c2.GeneratorScale(xrm); err != nil { // c2 = g^(rx + m)
		b.Fatal(err)
	}
	one := G.ZeroScalar()
	if _, err := one.SetBytes([]byte{0x01}); err != nil {
		b.Fatal(err)
	}
	g := G.Identity()
	if _, err := g.GeneratorScale(one); err != nil { // g
		b.Fatal(err)
	}
	y := G.Identity()
	if _, err := y.GeneratorScale(x); err != nil { // public key = g^x
		b.Fatal(err)
	}

	// Pedersen commitment
	h := G.Identity()
	xx, err := x.SetReader(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	if _, err := h.GeneratorScale(xx); err != nil { // Pedersen random generator h
		b.Fatal(err)
	}

	k := G.ZeroScalar()
	if _, err := k.SetReader(rand.Reader); err != nil { // Pedersen commitment randomness
		b.Fatal(err)
	}

	_, err = pedersen.Commit(m, k, &pedersen.CommitmentKey{Group: G, G: g, H: h}) // commitment = (g^m, h^k)
	if err != nil {
		b.Fatal(err)
	}

	// Proof that message in a ciphertext is the same as in a commitment
	opts := &CommitOpts{
		G:    G,
		PK:   y,
		H:    h,
		R:    r.Bytes(),
		R_:   k.Bytes(),
		M:    m.Bytes(),
		Prng: dprng.New(hash.SHA256),
	}

	commitment, _, err := Commit(rand.Reader, opts)

	prngs := dprng.New(hash.SHA256)
	out := make([]byte, (G.OrderBitLen()+7)/8)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		err = Challenge(prngs, out, commitment)
	}
	b.StopTimer()
	// 1056 ns/op	368 B/op	2 allocs/op

	fmt.Fprint(io.Discard, err)
}

func TestChallengeRegression(t *testing.T) {
	expected := 2.0

	G := nistec.NewP384Group(nistec.Params{PointEncodingBits: 10})

	plain := []byte("0000.102")
	m := G.ZeroScalar() // plaintext as scalar
	_, err := m.SetBytes(plain)
	if err != nil {
		t.Fatal(err)
	}

	x := G.ZeroScalar()
	if _, err := x.SetReader(rand.Reader); err != nil { // private key
		t.Fatal(err)
	}

	r := G.ZeroScalar()
	if _, err := r.SetReader(rand.Reader); err != nil { // encryption randomness
		t.Fatal(err)
	}

	// Lifted ElGamal
	c1 := G.Identity()
	_, err = c1.GeneratorScale(r) // c1 = g^r
	if err != nil {
		t.Fatal(err)
	}
	xrm := G.ZeroScalar()
	if _, err := xrm.Add(r); err != nil { // r
		t.Fatal(err)
	}
	if _, err := xrm.Mul(x); err != nil { // rx
		t.Fatal(err)
	}
	if _, err := xrm.Add(m); err != nil { // rx + m
		t.Fatal(err)
	}
	c2 := G.Identity()
	if _, err = c2.GeneratorScale(xrm); err != nil { // c2 = g^(rx + m)
		t.Fatal(err)
	}
	one := G.ZeroScalar()
	if _, err := one.SetBytes([]byte{0x01}); err != nil {
		t.Fatal(err)
	}
	g := G.Identity()
	if _, err := g.GeneratorScale(one); err != nil { // g
		t.Fatal(err)
	}
	y := G.Identity()
	if _, err := y.GeneratorScale(x); err != nil { // public key = g^x
		t.Fatal(err)
	}

	// Pedersen commitment
	h := G.Identity()
	xx, err := x.SetReader(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.GeneratorScale(xx); err != nil { // Pedersen random generator h
		t.Fatal(err)
	}

	k := G.ZeroScalar()
	if _, err := k.SetReader(rand.Reader); err != nil { // Pedersen commitment randomness
		t.Fatal(err)
	}

	_, err = pedersen.Commit(m, k, &pedersen.CommitmentKey{Group: G, G: g, H: h}) // commitment = (g^m, h^k)
	if err != nil {
		t.Fatal(err)
	}

	// Proof that message in a ciphertext is the same as in a commitment
	opts := &CommitOpts{
		G:    G,
		PK:   y,
		H:    h,
		R:    r.Bytes(),
		R_:   k.Bytes(),
		M:    m.Bytes(),
		Prng: dprng.New(hash.SHA256),
	}
	commitment, _, err := Commit(rand.Reader, opts)

	prngs := dprng.New(hash.SHA256)
	out := make([]byte, (G.OrderBitLen()+7)/8)

	if allocs := testing.AllocsPerRun(10, func() {
		err = Challenge(prngs, out, commitment)
	}); allocs > expected {
		t.Fatalf("Challenge now requires %0.f heap allocations, while before required %0.f", allocs, expected)
	}

	fmt.Fprint(io.Discard, err)
}

func BenchmarkResponse(b *testing.B) {
	G := nistec.NewP384Group(nistec.Params{PointEncodingBits: 10})

	plain := []byte("0000.102")
	m := G.ZeroScalar() // plaintext as scalar
	_, err := m.SetBytes(plain)
	if err != nil {
		b.Fatal(err)
	}

	x := G.ZeroScalar()
	if _, err := x.SetReader(rand.Reader); err != nil { // private key
		b.Fatal(err)
	}

	r := G.ZeroScalar()
	if _, err := r.SetReader(rand.Reader); err != nil { // encryption randomness
		b.Fatal(err)
	}

	// Lifted ElGamal
	c1 := G.Identity()
	_, err = c1.GeneratorScale(r) // c1 = g^r
	if err != nil {
		b.Fatal(err)
	}
	xrm := G.ZeroScalar()
	if _, err := xrm.Add(r); err != nil { // r
		b.Fatal(err)
	}
	if _, err := xrm.Mul(x); err != nil { // rx
		b.Fatal(err)
	}
	if _, err := xrm.Add(m); err != nil { // rx + m
		b.Fatal(err)
	}
	c2 := G.Identity()
	if _, err = c2.GeneratorScale(xrm); err != nil { // c2 = g^(rx + m)
		b.Fatal(err)
	}
	one := G.ZeroScalar()
	if _, err := one.SetBytes([]byte{0x01}); err != nil {
		b.Fatal(err)
	}
	g := G.Identity()
	if _, err := g.GeneratorScale(one); err != nil { // g
		b.Fatal(err)
	}
	y := G.Identity()
	if _, err := y.GeneratorScale(x); err != nil { // public key = g^x
		b.Fatal(err)
	}

	// Pedersen commitment
	h := G.Identity()
	xx, err := x.SetReader(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	if _, err := h.GeneratorScale(xx); err != nil { // Pedersen random generator h
		b.Fatal(err)
	}

	k := G.ZeroScalar()
	if _, err := k.SetReader(rand.Reader); err != nil { // Pedersen commitment randomness
		b.Fatal(err)
	}

	_, err = pedersen.Commit(m, k, &pedersen.CommitmentKey{Group: G, G: g, H: h}) // commitment = (g^m, h^k)
	if err != nil {
		b.Fatal(err)
	}

	// Proof that message in a ciphertext is the same as in a commitment
	opts := &CommitOpts{
		G:    G,
		PK:   y,
		H:    h,
		R:    r.Bytes(),
		R_:   k.Bytes(),
		M:    m.Bytes(),
		Prng: dprng.New(hash.SHA256),
	}

	commitment, respOpts, err := Commit(rand.Reader, opts)

	prngs := dprng.New(hash.SHA256)
	out := make([]byte, (G.OrderBitLen()+7)/8)
	err = Challenge(prngs, out, commitment)
	if err != nil {
		b.Fatal(err)
	}
	var resp []byte

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		resp, err = Response(out, respOpts)
	}
	b.StopTimer()
	// 1960 ns/op	896 B/op	10 allocs/op

	fmt.Fprint(io.Discard, resp, err)
}

func TestResponseRegression(t *testing.T) {
	expected := 10.0

	G := nistec.NewP384Group(nistec.Params{PointEncodingBits: 10})

	plain := []byte("0000.102")
	m := G.ZeroScalar() // plaintext as scalar
	_, err := m.SetBytes(plain)
	if err != nil {
		t.Fatal(err)
	}

	x := G.ZeroScalar()
	if _, err := x.SetReader(rand.Reader); err != nil { // private key
		t.Fatal(err)
	}

	r := G.ZeroScalar()
	if _, err := r.SetReader(rand.Reader); err != nil { // encryption randomness
		t.Fatal(err)
	}

	// Lifted ElGamal
	c1 := G.Identity()
	_, err = c1.GeneratorScale(r) // c1 = g^r
	if err != nil {
		t.Fatal(err)
	}
	xrm := G.ZeroScalar()
	if _, err := xrm.Add(r); err != nil { // r
		t.Fatal(err)
	}
	if _, err := xrm.Mul(x); err != nil { // rx
		t.Fatal(err)
	}
	if _, err := xrm.Add(m); err != nil { // rx + m
		t.Fatal(err)
	}
	c2 := G.Identity()
	if _, err = c2.GeneratorScale(xrm); err != nil { // c2 = g^(rx + m)
		t.Fatal(err)
	}
	one := G.ZeroScalar()
	if _, err := one.SetBytes([]byte{0x01}); err != nil {
		t.Fatal(err)
	}
	g := G.Identity()
	if _, err := g.GeneratorScale(one); err != nil { // g
		t.Fatal(err)
	}
	y := G.Identity()
	if _, err := y.GeneratorScale(x); err != nil { // public key = g^x
		t.Fatal(err)
	}

	// Pedersen commitment
	h := G.Identity()
	xx, err := x.SetReader(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.GeneratorScale(xx); err != nil { // Pedersen random generator h
		t.Fatal(err)
	}

	k := G.ZeroScalar()
	if _, err := k.SetReader(rand.Reader); err != nil { // Pedersen commitment randomness
		t.Fatal(err)
	}

	_, err = pedersen.Commit(m, k, &pedersen.CommitmentKey{Group: G, G: g, H: h}) // commitment = (g^m, h^k)
	if err != nil {
		t.Fatal(err)
	}

	// Proof that message in a ciphertext is the same as in a commitment
	opts := &CommitOpts{
		G:    G,
		PK:   y,
		H:    h,
		R:    r.Bytes(),
		R_:   k.Bytes(),
		M:    m.Bytes(),
		Prng: dprng.New(hash.SHA256),
	}
	commitment, respOpts, err := Commit(rand.Reader, opts)

	prngs := dprng.New(hash.SHA256)
	out := make([]byte, (G.OrderBitLen()+7)/8)
	err = Challenge(prngs, out, commitment)
	if err != nil {
		t.Fatal(err)
	}
	var resp []byte

	if allocs := testing.AllocsPerRun(10, func() {
		resp, err = Response(out, respOpts)
	}); allocs > expected {
		t.Fatalf("Response now requires %0.f heap allocations, while before required %0.f", allocs, expected)
	}

	fmt.Fprint(io.Discard, resp, err)
}

func BenchmarkVerify(b *testing.B) {
	G := nistec.NewP384Group(nistec.Params{PointEncodingBits: 10})

	plain := []byte("0000.102")
	m := G.ZeroScalar() // plaintext as scalar
	_, err := m.SetBytes(plain)
	if err != nil {
		b.Fatal(err)
	}

	x := G.ZeroScalar()
	if _, err := x.SetReader(rand.Reader); err != nil { // private key
		b.Fatal(err)
	}

	r := G.ZeroScalar()
	if _, err := r.SetReader(rand.Reader); err != nil { // encryption randomness
		b.Fatal(err)
	}

	// Lifted ElGamal
	c1 := G.Identity()
	_, err = c1.GeneratorScale(r) // c1 = g^r
	if err != nil {
		b.Fatal(err)
	}
	xrm := G.ZeroScalar()
	if _, err := xrm.Add(r); err != nil { // r
		b.Fatal(err)
	}
	if _, err := xrm.Mul(x); err != nil { // rx
		b.Fatal(err)
	}
	if _, err := xrm.Add(m); err != nil { // rx + m
		b.Fatal(err)
	}
	c2 := G.Identity()
	if _, err = c2.GeneratorScale(xrm); err != nil { // c2 = g^(rx + m)
		b.Fatal(err)
	}
	one := G.ZeroScalar()
	if _, err := one.SetBytes([]byte{0x01}); err != nil {
		b.Fatal(err)
	}
	g := G.Identity()
	if _, err := g.GeneratorScale(one); err != nil { // g
		b.Fatal(err)
	}
	y := G.Identity()
	if _, err := y.GeneratorScale(x); err != nil { // public key = g^x
		b.Fatal(err)
	}

	// Pedersen commitment
	h := G.Identity()
	xx, err := x.SetReader(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	if _, err := h.GeneratorScale(xx); err != nil { // Pedersen random generator h
		b.Fatal(err)
	}

	k := G.ZeroScalar()
	if _, err := k.SetReader(rand.Reader); err != nil { // Pedersen commitment randomness
		b.Fatal(err)
	}

	com, err := pedersen.Commit(m, k, &pedersen.CommitmentKey{Group: G, G: g, H: h}) // commitment = (g^m, h^k)
	if err != nil {
		b.Fatal(err)
	}

	// Proof that message in a ciphertext is the same as in a commitment
	opts := &CommitOpts{
		G:    G,
		PK:   y,
		H:    h,
		R:    r.Bytes(),
		R_:   k.Bytes(),
		M:    m.Bytes(),
		Prng: dprng.New(hash.SHA256),
	}

	commitment, respOpts, err := Commit(rand.Reader, opts)

	prngs := dprng.New(hash.SHA256)
	out := make([]byte, (G.OrderBitLen()+7)/8)
	err = Challenge(prngs, out, commitment)
	if err != nil {
		b.Fatal(err)
	}
	resp, err := Response(out, respOpts)
	if err != nil {
		b.Fatal(err)
	}

	verifyOpts := &VerifyOpts{
		G:  G,
		PK: y,
		H:  h,
		C1: c1,
		C2: c2,
		C3: com.Bytes(),
	}

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		err = Verify(commitment, out, resp, verifyOpts)
	}
	b.StopTimer()
	// 2878711 ns/op	1456 B/op	24 allocs/op

	fmt.Fprint(io.Discard, err)
}

func TestVerifyRegression(t *testing.T) {
	expected := 24.0

	G := nistec.NewP384Group(nistec.Params{PointEncodingBits: 10})

	plain := []byte("0000.102")
	m := G.ZeroScalar() // plaintext as scalar
	_, err := m.SetBytes(plain)
	if err != nil {
		t.Fatal(err)
	}

	x := G.ZeroScalar()
	if _, err := x.SetReader(rand.Reader); err != nil { // private key
		t.Fatal(err)
	}

	r := G.ZeroScalar()
	if _, err := r.SetReader(rand.Reader); err != nil { // encryption randomness
		t.Fatal(err)
	}

	// Lifted ElGamal
	c1 := G.Identity()
	_, err = c1.GeneratorScale(r) // c1 = g^r
	if err != nil {
		t.Fatal(err)
	}
	xrm := G.ZeroScalar()
	if _, err := xrm.Add(r); err != nil { // r
		t.Fatal(err)
	}
	if _, err := xrm.Mul(x); err != nil { // rx
		t.Fatal(err)
	}
	if _, err := xrm.Add(m); err != nil { // rx + m
		t.Fatal(err)
	}
	c2 := G.Identity()
	if _, err = c2.GeneratorScale(xrm); err != nil { // c2 = g^(rx + m)
		t.Fatal(err)
	}
	one := G.ZeroScalar()
	if _, err := one.SetBytes([]byte{0x01}); err != nil {
		t.Fatal(err)
	}
	g := G.Identity()
	if _, err := g.GeneratorScale(one); err != nil { // g
		t.Fatal(err)
	}
	y := G.Identity()
	if _, err := y.GeneratorScale(x); err != nil { // public key = g^x
		t.Fatal(err)
	}

	// Pedersen commitment
	h := G.Identity()
	xx, err := x.SetReader(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := h.GeneratorScale(xx); err != nil { // Pedersen random generator h
		t.Fatal(err)
	}

	k := G.ZeroScalar()
	if _, err := k.SetReader(rand.Reader); err != nil { // Pedersen commitment randomness
		t.Fatal(err)
	}

	com, err := pedersen.Commit(m, k, &pedersen.CommitmentKey{Group: G, G: g, H: h}) // commitment = (g^m, h^k)
	if err != nil {
		t.Fatal(err)
	}

	// Proof that message in a ciphertext is the same as in a commitment
	opts := &CommitOpts{
		G:    G,
		PK:   y,
		H:    h,
		R:    r.Bytes(),
		R_:   k.Bytes(),
		M:    m.Bytes(),
		Prng: dprng.New(hash.SHA256),
	}
	commitment, respOpts, err := Commit(rand.Reader, opts)

	prngs := dprng.New(hash.SHA256)
	out := make([]byte, (G.OrderBitLen()+7)/8)
	err = Challenge(prngs, out, commitment)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := Response(out, respOpts)
	if err != nil {
		t.Fatal(err)
	}

	verifyOpts := &VerifyOpts{
		G:  G,
		PK: y,
		H:  h,
		C1: c1,
		C2: c2,
		C3: com.Bytes(),
	}

	if allocs := testing.AllocsPerRun(10, func() {
		err = Verify(commitment, out, resp, verifyOpts)
	}); allocs > expected {
		t.Fatalf("Open now requires %0.f heap allocations, while before required %0.f", allocs, expected)
	}

	fmt.Fprint(io.Discard, err)
}
