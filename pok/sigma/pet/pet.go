// Package pet implements lifted ElGamal plaintext equality Sigma protocol which convinces
// a verifier that encoded message in a lifted ElGamal ciphertext is the same as in a
// Pedersen commitment of that encoded message.
package pet

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"gitlab.com/tivi-io/crypto/elgamal"
	"gitlab.com/tivi-io/crypto/elgamal/lifted"
	"gitlab.com/tivi-io/crypto/group"
	"gitlab.com/tivi-io/crypto/pok/commitment/pedersen"
)

// CommitOpts are mandatory options that define a commitment context.
type CommitOpts struct {
	PK *lifted.PublicKey
	CK *pedersen.CommitmentKey
	M  []byte // encoded message m
	R  []byte // encryption randomness r
	R_ []byte // commitment randomness r'
}

// Commit is used by a prover to commit a knowledge of an encoded message m in a commitment to be the
// same as in a lifted ElGamal ciphertext. This method returns commitment to be used in a challenge
// creation and options that should be used in a response creation.
//
// NB! Commitment slice returned is not a group element, but is rather a group
// of elements, and must be used in [Response] and [Verify] as is.
func Commit(rand io.Reader, opts *CommitOpts) ([]byte, *ResponseOpts, error) {
	if err := opts.PK.Validate(); err != nil {
		return nil, nil, fmt.Errorf("failed to validate lifted ElGamal public key: %v", err)
	}

	if err := opts.CK.Validate(); err != nil {
		return nil, nil, fmt.Errorf("failed to validate Pedersen commitment key: %v", err)
	}

	// These 3 variables below don't have special meaning and are just used as a temporary storage for
	// calculation results, pay attention to code comments as there are direct links to the algorithm
	E1 := opts.PK.G.Identity()
	E2 := opts.PK.G.Identity()
	s1 := opts.PK.G.ZeroScalar()

	// [group.Scalar.SetReader] guarantees that r̅ ∈ ℤq, r̅ > 0
	if _, err := s1.SetReader(rand); err != nil {
		return nil, nil, err
	}
	r_ := s1.Bytes()                                 // capture r̅
	if _, err := E1.GeneratorScale(s1); err != nil { // g^r̅
		return nil, nil, err
	}
	d_1 := E1.Bytes()
	// Ideally, d_1, d_2 and d_3 are non-identities, practically, only d_1 must be
	// non-identity, while d_2 and d_3 can legitimately be identities and therefore
	// commitment slice is not uniform in size. That's why we allocate ideal space
	// for all commitments and then later, on return, slice it on the actual size
	commitment := make([]byte, 3*len(d_1))
	subtle.ConstantTimeCopy(1, commitment[:len(d_1)], d_1) // d_1

	E1.SetIdentity()
	if _, err := E1.Op(opts.PK.Y); err != nil { // pk
		return nil, nil, err
	}
	if _, err := E1.Scale(s1); err != nil { // pk^r̅
		return nil, nil, err
	}
	// [group.Scalar.SetReader] guarantees that m̅ ∈ ℤq, m̅ > 0
	if _, err := s1.SetReader(rand); err != nil {
		return nil, nil, err
	}
	if _, err := E2.GeneratorScale(s1); err != nil { // g^m̅
		return nil, nil, err
	}
	m_ := s1.Bytes()                     // capture m̅
	if _, err := E1.Op(E2); err != nil { // g^m̅* pk^r̅
		return nil, nil, err
	}
	d_2 := E1.Bytes()
	subtle.ConstantTimeCopy(1, commitment[len(d_1):len(d_1)+len(d_2)], d_2) // d_2

	E1.SetIdentity()
	if _, err := E1.Op(opts.CK.H); err != nil { // h
		return nil, nil, err
	}
	// [group.Scalar.SetReader] guarantees that r̅' ∈ ℤq, r̅' > 0
	if _, err := s1.SetReader(rand); err != nil {
		return nil, nil, err
	}
	r__ := s1.Bytes()                       // capture r̅'
	if _, err := E1.Scale(s1); err != nil { // h^r̅'
		return nil, nil, err
	}
	if _, err := E2.Op(E1); err != nil { // g^m̅* h^r̅'
		return nil, nil, err
	}
	d_3 := E2.Bytes()
	subtle.ConstantTimeCopy(1, commitment[len(d_1)+len(d_2):len(d_1)+len(d_2)+len(d_3)], d_3) // d_3

	// Return actual commitment slice, as d_2 and d_3 might be identities, and, for
	// example, nistec groups encode identity as a single-byte slice [0x00]
	return commitment[:len(d_1)+len(d_2)+len(d_3)], &ResponseOpts{
		G:    opts.PK.G,
		M:    opts.M,
		R:    opts.R,
		R_:   opts.R_,
		M__:  m_,
		R__:  r_,
		R___: r__,
	}, nil
}

// ResponseOpts are mandatory options that define a response context.
type ResponseOpts struct {
	G    group.Group // group to which all elements in this opts belong
	M    []byte      // encoded message m
	R    []byte      // encryption randomness r
	R_   []byte      // commitment randomness r'
	M__  []byte      // Sigma protocol randomness m̅
	R__  []byte      // Sigma protocol randomness r̅
	R___ []byte      // Sigma protocol randomness r̅'
}

// Response is a prover response to the challenge.
//
// NB! Response slice returned is not a group scalar, but is rather a group
// of scalars, and must be used in [Verify] as is.
//
// SECURITY NOTE: Response is only intended to be run once per interaction, reusing
// the same opts twice with a different challenge will leak m (message),
// r (encryption randomness) and r' (commitment randomness) immediately as
// m = ((m̅ + y₁*m) - (m̅ + y₂*m))/(y₁ - y₂), then
// r = ((r̅ + y₁*r) - (r̅ + y₂*r))/(y₁ - y₂), and eventually
// r' = ((r̅' + y₁*r') - (r̅' + y₂*r'))/(y₁ - y₂) (soundness property).
func Response(challenge []byte, opts *ResponseOpts) ([]byte, error) {
	idx := (opts.G.OrderBitLen() + 7) / 8 // to point at a response (all 3 responses stored in a single slice)

	resp := make([]byte, 3*idx) // {m_y, r_y, r_y'}

	// These 2 variables below don't have special meaning and are just used as a temporary storage for
	// calculation results, pay attention to code comments as there are direct links to the algorithm
	s1 := opts.G.ZeroScalar()
	s2 := opts.G.ZeroScalar()

	if _, err := s1.SetBytes(challenge); err != nil { // γ
		return nil, err
	}
	if s1.IsZero() {
		return nil, errors.New("challenge cannot be a zero")
	}

	if _, err := s2.SetBytes(opts.M); err != nil { // m
		return nil, err
	}
	if _, err := s1.Mul(s2); err != nil { //  γ*m
		return nil, err
	}
	if _, err := s2.SetBytes(opts.M__); err != nil { // m̅
		return nil, err
	}
	if s2.IsZero() {
		return nil, errors.New("randomness m of Sigma protocol cannot be a zero")
	}

	if _, err := s2.Add(s1); err != nil { // m̅+ γ*m
		return nil, err
	}
	m_y := s2.Bytes()
	subtle.ConstantTimeCopy(1, resp[:idx], m_y) // m_y

	if _, err := s1.SetBytes(challenge); err != nil { // γ
		return nil, err
	}
	if _, err := s2.SetBytes(opts.R); err != nil { // r
		return nil, err
	}
	if _, err := s1.Mul(s2); err != nil { // γ*r
		return nil, err
	}
	if _, err := s2.SetBytes(opts.R__); err != nil { // r̅
		return nil, err
	}
	if s2.IsZero() {
		return nil, errors.New("randomness r of Sigma protocol cannot be a zero")
	}

	if _, err := s2.Add(s1); err != nil { // r̅+ γ*r
		return nil, err
	}
	r_y := s2.Bytes()
	subtle.ConstantTimeCopy(1, resp[idx:idx*2], r_y) // r_y

	if _, err := s1.SetBytes(challenge); err != nil { // γ
		return nil, err
	}
	if _, err := s2.SetBytes(opts.R_); err != nil { // r'
		return nil, err
	}
	if _, err := s1.Mul(s2); err != nil { // γ*r'
		return nil, err
	}
	if _, err := s2.SetBytes(opts.R___); err != nil { // r̅'
		return nil, err
	}
	if s2.IsZero() {
		return nil, errors.New("randomness r' of Sigma protocol cannot be a zero")
	}

	if _, err := s2.Add(s1); err != nil { // r̅' + γ*r'
		return nil, err
	}
	r_y_ := s2.Bytes()
	subtle.ConstantTimeCopy(1, resp[idx*2:], r_y_) // r_y'

	return resp, nil
}

// VerifyOpts are mandatory options that define a verifier context.
type VerifyOpts struct {
	PK         *lifted.PublicKey
	CK         *pedersen.CommitmentKey
	Ciphertext *elgamal.Ciphertext
	C3         []byte // Pedersen commitment
}

// Verify verifies that encoded message m in a commitment is the same as in a lifted ElGamal ciphertext.
func Verify(commitment, challenge, response []byte, opts *VerifyOpts) error { //nolint:gocyclo
	if err := opts.PK.Validate(); err != nil {
		return fmt.Errorf("failed to validate lifted ElGamal public key: %v", err)
	}

	if err := opts.CK.Validate(); err != nil {
		return fmt.Errorf("failed to validate Pedersen commitment key: %v", err)
	}

	idx := (opts.PK.G.OrderBitLen() + 7) / 8 // to point at a response (all 3 responses stored in a single slice)

	if len(response) != 3*idx { // to prevent panic on slicing
		return errors.New("invalid response binary representation")
	}

	// These 3 variables below don't have special meaning and are just used as a temporary storage for
	// calculation results, pay attention to code comments as there are direct links to the algorithm
	E1 := opts.PK.G.Identity()
	E2 := opts.PK.G.Identity()
	s1 := opts.PK.G.ZeroScalar()

	if _, err := s1.SetBytes(response[idx : idx*2]); err != nil { // r_y
		return err
	}
	if _, err := E1.GeneratorScale(s1); err != nil { // g^r_y
		return err
	}
	if _, err := E2.Op(opts.Ciphertext.C1); err != nil { // C_1
		return err
	}
	if _, err := s1.SetBytes(challenge); err != nil { // γ
		return err
	}
	if s1.IsZero() {
		return errors.New("challenge cannot be a zero")
	}

	if _, err := E2.Scale(s1); err != nil { // C_1^γ
		return err
	}
	if _, err := E1.Op(E2.Inverse()); err != nil { // g^r_y / C_1^γ
		return err
	}
	// d₁ = g^r̅, where g ≠ identity and r̅ > 0, so d₁ ≠ identity
	if E1.IsIdentity() {
		return errors.New("d_1 commitment cannot be an identity")
	}

	d_1 := E1.Bytes()               // d_1
	if len(commitment) < len(d_1) { // prevent panic during slicing d_1 out
		return errors.New("invalid d_1 commitment binary representation")
	}

	if subtle.ConstantTimeCompare(d_1, commitment[:len(d_1)]) != 1 {
		return errors.New("invalid commitment d_1")
	}

	E1.SetIdentity()
	if _, err := s1.SetBytes(response[:idx]); err != nil { // m_y
		return err
	}
	if _, err := E1.GeneratorScale(s1); err != nil { // g^m_y
		return err
	}
	b := E1.Bytes() // capture g^m_y
	E2.SetIdentity()
	if _, err := E2.Op(opts.PK.Y); err != nil { // pk
		return err
	}
	if _, err := s1.SetBytes(response[idx : idx*2]); err != nil { // r_y
		return err
	}
	if _, err := E2.Scale(s1); err != nil { // pk^r_y
		return err
	}
	if _, err := E1.Op(E2); err != nil { // g^m_y * pk^r_y
		return err
	}
	E2.SetIdentity()
	if _, err := E2.Op(opts.Ciphertext.C2); err != nil { // C_2
		return err
	}
	if _, err := s1.SetBytes(challenge); err != nil { // γ
		return err
	}
	if _, err := E2.Scale(s1); err != nil { // C_2^γ
		return err
	}
	if _, err := E1.Op(E2.Inverse()); err != nil { // (g^m_y * pk^r_y) / C_2^γ
		return err
	}
	d_2 := E1.Bytes()                        // d_2
	if len(commitment) < len(d_1)+len(d_2) { // prevent panic during slicing d_2 out
		return errors.New("invalid d_2 commitment binary representation")
	}

	if subtle.ConstantTimeCompare(d_2, commitment[len(d_1):len(d_1)+len(d_2)]) != 1 {
		return errors.New("invalid commitment d_2")
	}

	E1.SetIdentity()
	if _, err := E2.SetBytes(b); err != nil { // g^m_y
		return err
	}
	if _, err := E1.Op(opts.CK.H); err != nil { // h
		return err
	}
	if _, err := s1.SetBytes(response[idx*2:]); err != nil { // r_y'
		return err
	}
	if _, err := E1.Scale(s1); err != nil { // h^r_y'
		return err
	}
	if _, err := E2.Op(E1); err != nil { // g^m_y * h^r_y'
		return err
	}
	if _, err := E1.SetBytes(opts.C3); err != nil { // C_3
		return err
	}
	if _, err := s1.SetBytes(challenge); err != nil { // γ
		return err
	}
	if _, err := E1.Scale(s1); err != nil { // C_3^γ
		return err
	}
	if _, err := E2.Op(E1.Inverse()); err != nil { // (g^m_y * h^r_y') / C_3^γ
		return err
	}
	d_3 := E2.Bytes()                                  // d_3
	if len(commitment) != len(d_1)+len(d_2)+len(d_3) { // malformed d_3
		return errors.New("invalid d_3 commitment binary representation")
	}

	if subtle.ConstantTimeCompare(d_3, commitment[len(d_1)+len(d_2):]) != 1 {
		return errors.New("invalid commitment d_3")
	}

	return nil
}
