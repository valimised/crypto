// Package pet implements interactive lifted ElGamal plaintext equality Sigma protocol which
// convinces a verifier that encoded message in a lifted ElGamal ciphertext is the same as in
// a commitment of that encoded message. Non-interactivity can be achieved if prover calls Commit,
// Challenge and Response on its side.
package pet

import (
	"crypto/subtle"
	"errors"
	"io"

	"gitlab.com/tivi-io/crypto/group"
)

// CommitOpts are mandatory options that define a commitment context.
type CommitOpts struct {
	G  group.Group   // group to which all elements in this opts belong
	PK group.Element // public key material
	H  group.Element // commitment key generator h
	M  []byte        // encoded message m
	R  []byte        // encryption randomness r
	R_ []byte        // commitment randomness r'
}

// Commit is used by a prover to commit a knowledge of an encoded message m in a commitment to be the
// same as in a lifted ElGamal ciphertext. This method returns commitment to be used in a challenge
// creation and options that should be used in a response creation.
func Commit(rand io.Reader, opts *CommitOpts) ([]byte, *ResponseOpts, error) {
	// These 3 variables below don't have special meaning and are just used as a temporary storage for
	// calculation results, pay attention to code comments as there are direct links to the algorithm
	E1 := opts.G.Identity()
	E2 := opts.G.Identity()
	s1 := opts.G.ZeroScalar()

	if _, err := s1.SetReader(rand); err != nil { // r̅
		return nil, nil, err
	}
	r_ := s1.Bytes()                                 // capture r̅
	if _, err := E1.GeneratorScale(s1); err != nil { // g^r̅
		return nil, nil, err
	}
	d_1 := E1.Bytes()
	commitment := make([]byte, 3*len(d_1))                 // single slice to hold all 3 commitments
	subtle.ConstantTimeCopy(1, commitment[:len(d_1)], d_1) // d_1

	E1.SetIdentity()
	if _, err := E1.Op(opts.PK); err != nil { // pk
		return nil, nil, err
	}
	if _, err := E1.Scale(s1); err != nil { // pk^r̅
		return nil, nil, err
	}
	if _, err := s1.SetReader(rand); err != nil { // m̅
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
	subtle.ConstantTimeCopy(1, commitment[len(d_2):len(d_2)*2], d_2) // d_2

	E1.SetIdentity()
	if _, err := E1.Op(opts.H); err != nil { // h
		return nil, nil, err
	}
	if _, err := s1.SetReader(rand); err != nil { // r̅'
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
	subtle.ConstantTimeCopy(1, commitment[len(d_3)*2:], d_3) // d_3

	return commitment, &ResponseOpts{
		G:    opts.G,
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
	if _, err := s2.SetBytes(opts.M); err != nil { // m
		return nil, err
	}
	if _, err := s1.Mul(s2); err != nil { //  γ*m
		return nil, err
	}
	if _, err := s2.SetBytes(opts.M__); err != nil { // m̅
		return nil, err
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
	if _, err := s2.Add(s1); err != nil { // r̅' + γ*r'
		return nil, err
	}
	r_y_ := s2.Bytes()
	subtle.ConstantTimeCopy(1, resp[idx*2:], r_y_) // r_y'

	return resp, nil
}

// VerifyOpts are mandatory options that define a verifier context.
type VerifyOpts struct {
	G      group.Group   // group to which all elements in this opts belong
	PK     group.Element // public key material
	H      group.Element // commitment key generator h
	C1, C2 group.Element // ElGamal ciphertext (c1,c2)
	C3     []byte        // commitment
}

// Verify verifies that encoded message m in a commitment is the same as in a lifted ElGamal ciphertext.
func Verify(commitment, challenge, response []byte, opts *VerifyOpts) error {
	idx := (opts.G.OrderBitLen() + 7) / 8 // to point at a response (all 3 responses stored in a single slice)

	// These 3 variables below don't have special meaning and are just used as a temporary storage for
	// calculation results, pay attention to code comments as there are direct links to the algorithm
	E1 := opts.G.Identity()
	E2 := opts.G.Identity()
	s1 := opts.G.ZeroScalar()

	if _, err := s1.SetBytes(response[idx : idx*2]); err != nil { // r_y
		return err
	}
	if _, err := E1.GeneratorScale(s1); err != nil { // g^r_y
		return err
	}
	if _, err := E2.Op(opts.C1); err != nil { // C_1
		return err
	}
	if _, err := s1.SetBytes(challenge); err != nil { // γ
		return err
	}
	if _, err := E2.Scale(s1); err != nil { // C_1^γ
		return err
	}
	if _, err := E1.Op(E2.Inverse()); err != nil { // g^r_y / C_1^γ
		return err
	}
	d_1 := E1.Bytes() // d_1
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
	if _, err := E2.Op(opts.PK); err != nil { // pk
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
	if _, err := E2.Op(opts.C2); err != nil { // C_2
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
	d_2 := E1.Bytes() // d_2
	if subtle.ConstantTimeCompare(d_2, commitment[len(d_2):len(d_2)*2]) != 1 {
		return errors.New("invalid commitment d_2")
	}

	E1.SetIdentity()
	if _, err := E2.SetBytes(b); err != nil { // g^m_y
		return err
	}
	if _, err := E1.Op(opts.H); err != nil { // h
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
	d_3 := E2.Bytes() // d_3
	if subtle.ConstantTimeCompare(d_3, commitment[len(d_3)*2:]) != 1 {
		return errors.New("invalid commitment d_3")
	}

	return nil
}
