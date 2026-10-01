package membership

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"
	"testing"

	"gitlab.com/tivi-io/crypto/group/nistec"
	"gitlab.com/tivi-io/crypto/hash"
	"gitlab.com/tivi-io/crypto/pok/commitment/pedersen"
	"gitlab.com/tivi-io/crypto/pok/nizk"
	"gitlab.com/tivi-io/crypto/prng/dprng"
)

func TestProveVerifyWhenActualChoiceAndCommittedChoiceDiffer(t *testing.T) {
	G := nistec.NewP384Group(nistec.Params{PointEncodingBits: 10})
	one, err := G.ZeroScalar().SetBytes([]byte{0x01})
	if err != nil {
		t.Fatal(err)
	}
	x, err := G.ZeroScalar().SetReader(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	g, err := G.Identity().GeneratorScale(one)
	if err != nil {
		t.Fatal(err)
	}
	h, err := g.GeneratorScale(x)
	if err != nil {
		t.Fatal(err)
	}

	publicListSize := 16
	publicList := make([][]byte, publicListSize)
	for i := 0; i < publicListSize; i++ { // Fill custom choices
		publicList[i] = []byte("0000." + fmt.Sprintf("%03d", i))

	}

	opts := &pedersen.CommitmentKey{Group: G, G: g, H: h}
	choice := 2                                       // I have chosen index 2 out of a public list of 16 choices
	c, err := G.ZeroScalar().SetBytes(publicList[15]) // note that I commit index 15
	if err != nil {
		t.Fatal(err)
	}
	r, err := G.ZeroScalar().SetReader(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	committedChoice, err := pedersen.Commit(c, r, opts)
	if err != nil {
		t.Fatal(err)
	}

	commitment, respOpts, err := Commit(rand.Reader,
		&CommitOpts{
			Group: G,
			G:     g,
			H:     h,
			R:     r.Bytes(),
			L:     choice,
			List:  publicList,
		})
	if err != nil {
		t.Fatal(err)
	}

	out := make([]byte, (G.OrderBitLen()+7)/8)
	byteLen := len(commitment[0])
	com := make([]byte, byteLen*len(commitment))
	for i := range commitment {
		subtle.ConstantTimeCopy(1, com[i*byteLen:(i*byteLen)+byteLen], commitment[i])
	}
	err = nizk.Challenge(dprng.New(hash.SHA256).Seed(com), G, out)
	if err != nil {
		t.Fatal(err)
	}

	response, err := Response(out, respOpts)
	if err != nil {
		t.Fatal(err)
	}

	err = Verify(commitment, out, response, &VerifyOpts{
		Group:      G,
		G:          g,
		H:          h,
		Commitment: committedChoice.Bytes(),
		List:       publicList,
	})

	if err.Error() != "verification step 3 failed" {
		t.Fatalf("expected error='verification step 3 failed', got=%v", err)
	}
}

func TestProveVerifyWhenActualChoiceIsNotInAPublicList(t *testing.T) {
	G := nistec.NewP384Group(nistec.Params{PointEncodingBits: 10})
	one, err := G.ZeroScalar().SetBytes([]byte{0x01})
	if err != nil {
		t.Fatal(err)
	}
	x, err := G.ZeroScalar().SetReader(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	g, err := G.Identity().GeneratorScale(one)
	if err != nil {
		t.Fatal(err)
	}
	h, err := g.GeneratorScale(x)
	if err != nil {
		t.Fatal(err)
	}

	publicListSize := 1000
	publicList := make([][]byte, publicListSize)
	for i := range publicListSize {
		publicList[i] = []byte("0000." + fmt.Sprintf("%03d", i))

	}

	opts := &pedersen.CommitmentKey{Group: G, G: g, H: h}
	c, err := G.ZeroScalar().SetBytes(publicList[2]) // note that committed choice is within a public list
	if err != nil {
		t.Fatal(err)
	}
	choice := 1001 // but choice is out of a list (1001 out of 1000)
	r, err := G.ZeroScalar().SetReader(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	committedChoice, err := pedersen.Commit(c, r, opts)
	if err != nil {
		t.Fatal(err)
	}

	commitment, respOpts, err := Commit(rand.Reader,
		&CommitOpts{
			Group: G,
			G:     g,
			H:     h,
			R:     r.Bytes(),
			L:     choice,
			List:  publicList,
		})
	if err != nil {
		t.Fatal(err)
	}

	out := make([]byte, (G.OrderBitLen()+7)/8)
	byteLen := len(commitment[0])
	com := make([]byte, byteLen*len(commitment))
	for i := range commitment {
		subtle.ConstantTimeCopy(1, com[i*byteLen:(i*byteLen)+byteLen], commitment[i])
	}
	err = nizk.Challenge(dprng.New(hash.SHA256).Seed(com), G, out)
	if err != nil {
		t.Fatal(err)
	}

	response, err := Response(out, respOpts)
	if err != nil {
		t.Fatal(err)
	}

	err = Verify(commitment, out, response, &VerifyOpts{
		Group:      G,
		G:          g,
		H:          h,
		Commitment: committedChoice.Bytes(),
		List:       publicList,
	})

	if err.Error() != "verification step 3 failed" {
		t.Fatalf("expected error='verification step 3 failed', got=%v", err)
	}
}

func TestProveVerifyWhenCommittedChoiceIsNotInAPublicList(t *testing.T) {
	G := nistec.NewP384Group(nistec.Params{PointEncodingBits: 10})
	one, err := G.ZeroScalar().SetBytes([]byte{0x01})
	if err != nil {
		t.Fatal(err)
	}
	x, err := G.ZeroScalar().SetReader(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	g, err := G.Identity().GeneratorScale(one)
	if err != nil {
		t.Fatal(err)
	}
	h, err := g.GeneratorScale(x)
	if err != nil {
		t.Fatal(err)
	}

	publicListSize := 3
	publicList := make([][]byte, publicListSize)
	for i := range publicListSize {
		publicList[i] = []byte("0000." + fmt.Sprintf("%03d", i))

	}

	opts := &pedersen.CommitmentKey{Group: G, G: g, H: h}
	choice := 1                                           // choice is within a public list
	c, err := G.ZeroScalar().SetBytes([]byte("0000.003")) // but committed choice is not in a public list
	if err != nil {
		t.Fatal(err)
	}
	r, err := G.ZeroScalar().SetReader(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	committedChoice, err := pedersen.Commit(c, r, opts)
	if err != nil {
		t.Fatal(err)
	}

	commitment, respOpts, err := Commit(rand.Reader,
		&CommitOpts{
			Group: G,
			G:     g,
			H:     h,
			R:     r.Bytes(),
			L:     choice,
			List:  publicList,
		})
	if err != nil {
		t.Fatal(err)
	}

	out := make([]byte, (G.OrderBitLen()+7)/8)
	byteLen := len(commitment[0])
	com := make([]byte, byteLen*len(commitment))
	for i := range commitment {
		subtle.ConstantTimeCopy(1, com[i*byteLen:(i*byteLen)+byteLen], commitment[i])
	}
	err = nizk.Challenge(dprng.New(hash.SHA256).Seed(com), G, out)
	if err != nil {
		t.Fatal(err)
	}

	response, err := Response(out, respOpts)
	if err != nil {
		t.Fatal(err)
	}

	err = Verify(commitment, out, response, &VerifyOpts{
		Group:      G,
		G:          g,
		H:          h,
		Commitment: committedChoice.Bytes(),
		List:       publicList,
	})

	if err.Error() != "verification step 3 failed" {
		t.Fatalf("expected error='verification step 3 failed', got=%v", err)
	}
}

func TestProveVerify(t *testing.T) {
	G := nistec.NewP384Group(nistec.Params{PointEncodingBits: 10})
	one, err := G.ZeroScalar().SetBytes([]byte{0x01})
	if err != nil {
		t.Fatal(err)
	}
	x, err := G.ZeroScalar().SetReader(rand.Reader)

	if err != nil {
		t.Fatal(err)
	}
	g, err := G.Identity().GeneratorScale(one) // g
	if err != nil {
		t.Fatal(err)
	}
	h, err := g.GeneratorScale(x) // g^x
	if err != nil {
		t.Fatal(err)
	}

	publicListSize := 8
	publicList := make([][]byte, publicListSize)
	j := 1
	for i := range publicListSize { // Fill custom choices
		publicList[i] = []byte("0000." + fmt.Sprintf("%03d", j))
		j++
	}

	opts := &pedersen.CommitmentKey{Group: G, G: g, H: h}
	choice := 2                                           // I have chosen index 2 out of a public list of 8 choices
	c, err := G.ZeroScalar().SetBytes(publicList[choice]) // choice as scalar
	if err != nil {
		t.Fatal(err)
	}
	r, err := G.ZeroScalar().SetReader(rand.Reader) // randomness for choice commitment
	if err != nil {
		t.Fatal(err)
	}
	committedChoice, err := pedersen.Commit(c, r, opts)
	if err != nil {
		t.Fatal(err)
	}

	// Prover --> Verifier
	commitment, proveOpts, err := Commit(rand.Reader,
		&CommitOpts{
			Group: G,
			G:     g,
			H:     h,
			R:     r.Bytes(),
			L:     choice,
			List:  publicList,
		})
	if err != nil {
		t.Fatal(err)
	}

	// Prover <-- Verifier (note that in case of non-interactive proof, this step is done on Prover side)
	out := make([]byte, (G.OrderBitLen()+7)/8)
	byteLen := len(commitment[0])
	com := make([]byte, byteLen*len(commitment))
	for i := range commitment {
		subtle.ConstantTimeCopy(1, com[i*byteLen:(i*byteLen)+byteLen], commitment[i])
	}
	err = nizk.Challenge(dprng.New(hash.SHA256).Seed(com), G, out)
	if err != nil {
		t.Fatal(err)
	}

	// Prover --> Verifier
	response, err := Response(out, proveOpts)
	if err != nil {
		t.Fatal(err)
	}

	// Prover <-- Verifier (note that in case of non-interactive proof, Challenge is called on Verifier side as well
	// to generate a challenge out of provided Prover commitments)
	if err = Verify(commitment, out, response, &VerifyOpts{
		Group:      G,
		G:          g,
		H:          h,
		Commitment: committedChoice.Bytes(),
		List:       publicList,
	}); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkCommit(b *testing.B) {
	G := nistec.NewP384Group(nistec.Params{PointEncodingBits: 10})
	one, err := G.ZeroScalar().SetBytes([]byte{0x01})
	if err != nil {
		b.Fatal(err)
	}
	x, err := G.ZeroScalar().SetReader(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	g, err := G.Identity().GeneratorScale(one)
	if err != nil {
		b.Fatal(err)
	}
	h, err := g.GeneratorScale(x)
	if err != nil {
		b.Fatal(err)
	}

	publicListSize := 1000
	publicList := make([][]byte, publicListSize)
	for i := range publicListSize {
		publicList[i] = []byte("0000." + fmt.Sprintf("%03d", i))

	}

	choice := 998
	r, err := G.ZeroScalar().SetReader(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	var commitment [][]byte
	var respOpts *ResponseOpts

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		commitment, respOpts, err = Commit(rand.Reader,
			&CommitOpts{
				Group: G,
				G:     g,
				H:     h,
				R:     r.Bytes(),
				L:     choice,
				List:  publicList,
			})
	}
	b.StopTimer()
	// 75470010 ns/op	35984 B/op	412 allocs/op

	fmt.Fprint(io.Discard, commitment, respOpts, err)
}

func TestCommitRegression(t *testing.T) {
	expected := 412.0

	G := nistec.NewP384Group(nistec.Params{PointEncodingBits: 10})
	one, err := G.ZeroScalar().SetBytes([]byte{0x01})
	if err != nil {
		t.Fatal(err)
	}
	x, err := G.ZeroScalar().SetReader(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	g, err := G.Identity().GeneratorScale(one)
	if err != nil {
		t.Fatal(err)
	}
	h, err := g.GeneratorScale(x)
	if err != nil {
		t.Fatal(err)
	}

	publicListSize := 1000
	publicList := make([][]byte, publicListSize)
	for i := range publicListSize {
		publicList[i] = []byte("0000." + fmt.Sprintf("%03d", i))

	}

	choice := 998
	r, err := G.ZeroScalar().SetReader(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var commitment [][]byte
	var respOpts *ResponseOpts

	if allocs := testing.AllocsPerRun(10, func() {
		commitment, respOpts, err = Commit(rand.Reader,
			&CommitOpts{
				Group: G,
				G:     g,
				H:     h,
				R:     r.Bytes(),
				L:     choice,
				List:  publicList,
			})
	}); allocs > expected {
		t.Fatalf("Commit now requires %0.f heap allocations, while before required %0.f", allocs, expected)
	}

	fmt.Fprint(io.Discard, commitment, respOpts, err)
}

func BenchmarkResponse(b *testing.B) {
	G := nistec.NewP384Group(nistec.Params{PointEncodingBits: 10})
	one, err := G.ZeroScalar().SetBytes([]byte{0x01})
	if err != nil {
		b.Fatal(err)
	}
	x, err := G.ZeroScalar().SetReader(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	g, err := G.Identity().GeneratorScale(one)
	if err != nil {
		b.Fatal(err)
	}
	h, err := g.GeneratorScale(x)
	if err != nil {
		b.Fatal(err)
	}

	publicListSize := 1000
	publicList := make([][]byte, publicListSize)
	for i := range publicListSize {
		publicList[i] = []byte("0000." + fmt.Sprintf("%03d", i))

	}

	choice := 998
	r, err := G.ZeroScalar().SetReader(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	commitment, respOpts, err := Commit(rand.Reader,
		&CommitOpts{
			Group: G,
			G:     g,
			H:     h,
			R:     r.Bytes(),
			L:     choice,
			List:  publicList,
		})
	if err != nil {
		b.Fatal(err)
	}

	out := make([]byte, (G.OrderBitLen()+7)/8)
	byteLen := len(commitment[0])
	com := make([]byte, byteLen*len(commitment))
	for i := range commitment {
		subtle.ConstantTimeCopy(1, com[i*byteLen:(i*byteLen)+byteLen], commitment[i])
	}
	err = nizk.Challenge(dprng.New(hash.SHA256).Seed(com), G, out)
	if err != nil {
		b.Fatal(err)
	}
	var resp [][]byte

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		resp, err = Response(out, respOpts)
	}
	b.StopTimer()
	// 15853 ns/op	3168 B/op	41 allocs/op

	fmt.Fprint(io.Discard, resp, err)
}

func TestResponseRegression(t *testing.T) {
	expected := 41.0

	G := nistec.NewP384Group(nistec.Params{PointEncodingBits: 10})
	one, err := G.ZeroScalar().SetBytes([]byte{0x01})
	if err != nil {
		t.Fatal(err)
	}
	x, err := G.ZeroScalar().SetReader(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	g, err := G.Identity().GeneratorScale(one)
	if err != nil {
		t.Fatal(err)
	}
	h, err := g.GeneratorScale(x)
	if err != nil {
		t.Fatal(err)
	}

	publicListSize := 1000
	publicList := make([][]byte, publicListSize)
	for i := range publicListSize {
		publicList[i] = []byte("0000." + fmt.Sprintf("%03d", i))

	}

	choice := 998
	r, err := G.ZeroScalar().SetReader(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	commitment, respOpts, err := Commit(rand.Reader,
		&CommitOpts{
			Group: G,
			G:     g,
			H:     h,
			R:     r.Bytes(),
			L:     choice,
			List:  publicList,
		})
	if err != nil {
		t.Fatal(err)
	}

	out := make([]byte, (G.OrderBitLen()+7)/8)
	byteLen := len(commitment[0])
	com := make([]byte, byteLen*len(commitment))
	for i := range commitment {
		subtle.ConstantTimeCopy(1, com[i*byteLen:(i*byteLen)+byteLen], commitment[i])
	}
	err = nizk.Challenge(dprng.New(hash.SHA256).Seed(com), G, out)
	if err != nil {
		t.Fatal(err)
	}
	var resp [][]byte

	if allocs := testing.AllocsPerRun(10, func() {
		resp, err = Response(out, respOpts)
	}); allocs > expected {
		t.Fatalf("Response now requires %0.f heap allocations, while before required %0.f", allocs, expected)
	}

	fmt.Fprint(io.Discard, resp, err)
}

func BenchmarkVerify(b *testing.B) {
	G := nistec.NewP384Group(nistec.Params{PointEncodingBits: 10})
	one, err := G.ZeroScalar().SetBytes([]byte{0x01})
	if err != nil {
		b.Fatal(err)
	}
	x, err := G.ZeroScalar().SetReader(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	g, err := G.Identity().GeneratorScale(one)
	if err != nil {
		b.Fatal(err)
	}
	h, err := g.GeneratorScale(x)
	if err != nil {
		b.Fatal(err)
	}

	publicListSize := 1000
	publicList := make([][]byte, publicListSize)
	for i := range publicListSize {
		publicList[i] = []byte("0000." + fmt.Sprintf("%03d", i))

	}

	choice := 998
	r, err := G.ZeroScalar().SetReader(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	commitment, respOpts, err := Commit(rand.Reader,
		&CommitOpts{
			Group: G,
			G:     g,
			H:     h,
			R:     r.Bytes(),
			L:     choice,
			List:  publicList,
		})
	if err != nil {
		b.Fatal(err)
	}

	out := make([]byte, (G.OrderBitLen()+7)/8)
	byteLen := len(commitment[0])
	com := make([]byte, byteLen*len(commitment))
	for i := range commitment {
		subtle.ConstantTimeCopy(1, com[i*byteLen:(i*byteLen)+byteLen], commitment[i])
	}
	err = nizk.Challenge(dprng.New(hash.SHA256).Seed(com), G, out)
	if err != nil {
		b.Fatal(err)
	}

	resp, err := Response(out, respOpts)
	if err != nil {
		b.Fatal(err)
	}

	c, err := G.ZeroScalar().SetBytes(publicList[choice])
	if err != nil {
		b.Fatal(err)
	}
	opts := &pedersen.CommitmentKey{Group: G, G: g, H: h}
	committedChoice, err := pedersen.Commit(c, r, opts)
	if err != nil {
		b.Fatal(err)
	}

	verifyOpts := &VerifyOpts{
		Group:      G,
		G:          g,
		H:          h,
		Commitment: committedChoice.Bytes(),
		List:       publicList,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		err = Verify(commitment, out, resp, verifyOpts)
	}
	b.StopTimer()
	// 35984523 ns/op	5417 B/op	104 allocs/op

	fmt.Fprint(io.Discard, err)
}

func TestVerifyRegression(t *testing.T) {
	expected := 104.0

	G := nistec.NewP384Group(nistec.Params{PointEncodingBits: 10})
	one, err := G.ZeroScalar().SetBytes([]byte{0x01})
	if err != nil {
		t.Fatal(err)
	}
	x, err := G.ZeroScalar().SetReader(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	g, err := G.Identity().GeneratorScale(one)
	if err != nil {
		t.Fatal(err)
	}
	h, err := g.GeneratorScale(x)
	if err != nil {
		t.Fatal(err)
	}

	publicListSize := 1000
	publicList := make([][]byte, publicListSize)
	for i := range publicListSize {
		publicList[i] = []byte("0000." + fmt.Sprintf("%03d", i))

	}

	choice := 998
	r, err := G.ZeroScalar().SetReader(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	commitment, respOpts, err := Commit(rand.Reader,
		&CommitOpts{
			Group: G,
			G:     g,
			H:     h,
			R:     r.Bytes(),
			L:     choice,
			List:  publicList,
		})
	if err != nil {
		t.Fatal(err)
	}

	out := make([]byte, (G.OrderBitLen()+7)/8)
	byteLen := len(commitment[0])
	com := make([]byte, byteLen*len(commitment))
	for i := range commitment {
		subtle.ConstantTimeCopy(1, com[i*byteLen:(i*byteLen)+byteLen], commitment[i])
	}
	err = nizk.Challenge(dprng.New(hash.SHA256).Seed(com), G, out)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := Response(out, respOpts)
	if err != nil {
		t.Fatal(err)
	}

	c, err := G.ZeroScalar().SetBytes(publicList[choice])
	if err != nil {
		t.Fatal(err)
	}
	opts := &pedersen.CommitmentKey{Group: G, G: g, H: h}
	committedChoice, err := pedersen.Commit(c, r, opts)
	if err != nil {
		t.Fatal(err)
	}

	verifyOpts := &VerifyOpts{
		Group:      G,
		G:          g,
		H:          h,
		Commitment: committedChoice.Bytes(),
		List:       publicList,
	}

	if allocs := testing.AllocsPerRun(10, func() {
		err = Verify(commitment, out, resp, verifyOpts)
	}); allocs > expected {
		t.Fatalf("Verfiy now requires %0.f heap allocations, while before required %0.f", allocs, expected)
	}

	fmt.Fprint(io.Discard, err)
}

func fuzzSetup(f *testing.F) ([][]byte, []byte, [][]byte, *ResponseOpts, *VerifyOpts) {
	G := nistec.NewP384Group(nistec.Params{PointEncodingBits: 10})
	one, err := G.ZeroScalar().SetBytes([]byte{0x01})
	if err != nil {
		f.Fatal(err)
	}
	x, err := G.ZeroScalar().SetReader(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	g, err := G.Identity().GeneratorScale(one)
	if err != nil {
		f.Fatal(err)
	}
	h, err := g.GeneratorScale(x)
	if err != nil {
		f.Fatal(err)
	}

	publicListSize := 1000
	publicList := make([][]byte, publicListSize)
	for i := range publicListSize {
		publicList[i] = []byte("0000." + fmt.Sprintf("%03d", i))

	}

	choice := 998
	r, err := G.ZeroScalar().SetReader(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}

	commitment, respOpts, err := Commit(rand.Reader,
		&CommitOpts{
			Group: G,
			G:     g,
			H:     h,
			R:     r.Bytes(),
			L:     choice,
			List:  publicList,
		})
	if err != nil {
		f.Fatal(err)
	}

	out := make([]byte, (G.OrderBitLen()+7)/8)
	byteLen := len(commitment[0])
	com := make([]byte, byteLen*len(commitment))
	for i := range commitment {
		subtle.ConstantTimeCopy(1, com[i*byteLen:(i*byteLen)+byteLen], commitment[i])
	}
	err = nizk.Challenge(dprng.New(hash.SHA256).Seed(com), G, out)
	if err != nil {
		f.Fatal(err)
	}

	resp, err := Response(out, respOpts)
	if err != nil {
		f.Fatal(err)
	}

	c, err := G.ZeroScalar().SetBytes(publicList[choice])
	if err != nil {
		f.Fatal(err)
	}
	opts := &pedersen.CommitmentKey{Group: G, G: g, H: h}
	committedChoice, err := pedersen.Commit(c, r, opts)
	if err != nil {
		f.Fatal(err)
	}

	verifyOpts := &VerifyOpts{
		Group:      G,
		G:          g,
		H:          h,
		Commitment: committedChoice.Bytes(),
		List:       publicList,
	}

	return commitment, out, resp, respOpts, verifyOpts
}

func FuzzResponse(f *testing.F) {
	_, _, _, respOpts, _ := fuzzSetup(f)

	// Only catch panics
	f.Fuzz(func(t *testing.T, challenge []byte) {
		Response(challenge, respOpts)
	})
}

func FuzzVerifyCommitment(f *testing.F) {
	comm, challenge, response, _, verifyOpts := fuzzSetup(f)

	commitment2 := make([][]byte, len(comm))

	// Only catch panics
	f.Fuzz(func(t *testing.T, commitment []byte) {
		for i := range commitment2 {
			commitment2[i] = commitment
		}

		Verify(commitment2, challenge, response, verifyOpts)
	})
}

func FuzzVerifyChallenge(f *testing.F) {
	commitment, _, response, _, verifyOpts := fuzzSetup(f)

	// Only catch panics
	f.Fuzz(func(t *testing.T, challenge []byte) {
		Verify(commitment, challenge, response, verifyOpts)
	})
}

func FuzzVerifyResponse(f *testing.F) {
	commitment, challenge, resp, _, verifyOpts := fuzzSetup(f)

	response2 := make([][]byte, len(resp))

	// Only catch panics
	f.Fuzz(func(t *testing.T, response []byte) {
		for i := range response2 {
			response2[i] = response
		}

		Verify(commitment, challenge, response2, verifyOpts)
	})
}
