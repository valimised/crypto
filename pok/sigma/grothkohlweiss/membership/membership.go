// Package membership implements Groth-Kohlweiss interactive membership Sigma protocol using
// Pedersen commitment scheme. Non-interactivity can be achieved if prover calls Commit, Challenge
// and Response on its side. See also https://eprint.iacr.org/2014/764.pdf.
package membership

import (
	"errors"
	"io"

	"tivi.io/crypto/group"
	"tivi.io/crypto/pok/nizk"
	"tivi.io/crypto/prng"
)

// CommitOpts are mandatory options that define a commitment context.
type CommitOpts struct {
	Group group.Group   // group to which all elements in this opts belong
	G     group.Element // g param of a commitment key ck (g,h), which is used in Com_ck
	H     group.Element // h param of a commitment key ck (g,h), which is used in Com_ck
	List  [][]byte      // public list {λ_1, ..., λ_N}
	L     int           // index of a value from a public list
	R     []byte        // randomness used in a value commitment
}

// Commit is used by a prover to commit a knowledge of an index l of a value from a public list.
func Commit(rand io.Reader, opts *CommitOpts) ([][]byte, *ResponseOpts, error) {
	N := len(opts.List)
	n := 1
	twoN := 2 // 2^n
	for ; twoN < N; n++ {
		twoN <<= 1
	}

	commitments := make([][]byte, n*4) // {c_l1, ..., c_ln, c_a1, ..., c_an, c_b1, ..., c_bn, c_d0, ..., c_dn-1}

	// These 4 variables below don't have special meaning and are just used as a temporary storage for
	// calculation results, pay attention to code comments as there are direct links to the algorithm
	E1 := opts.Group.Identity()
	E2 := opts.Group.Identity()
	s1 := opts.Group.ZeroScalar()
	s2 := opts.Group.ZeroScalar()

	// r_j, a_j, s_j, t_j, ρ_k ← Zq
	r_j := make([]group.Scalar, n)
	a_j := make([]group.Scalar, n)
	s_j := make([]group.Scalar, n)
	t_j := make([]group.Scalar, n)
	p_k := make([]group.Scalar, n)

	var err error

	p_x := make([]group.Scalar, n+1) // p_x = (n)П(j=1)(f_j,i_j) = p_i,k + p_i,k+1 + ... + p_i,kn
	d_x := make([]group.Scalar, n+1) // d(x) = (N-1)∑(i=0)(m_i*p_i(x))
	p_x[0] = opts.Group.ZeroScalar().SetOne()
	for j := 1; j <= n; j++ {
		p_x[j] = opts.Group.ZeroScalar()
	}
	for j := 0; j <= n; j++ {
		d_x[j] = opts.Group.ZeroScalar()
	}

	// For j=1, ..., n using k=j-1
	for j, k, mask := 1, 0, 1; j <= n; j, k, mask = j+1, k+1, mask<<1 { // mask points to the bit of a binary value
		if r_j[j-1], err = opts.Group.ZeroScalar().SetReader(rand); err != nil {
			return nil, nil, err
		}
		if a_j[j-1], err = opts.Group.ZeroScalar().SetReader(rand); err != nil {
			return nil, nil, err
		}
		if s_j[j-1], err = opts.Group.ZeroScalar().SetReader(rand); err != nil {
			return nil, nil, err
		}
		if t_j[j-1], err = opts.Group.ZeroScalar().SetReader(rand); err != nil {
			return nil, nil, err
		}
		if p_k[k], err = opts.Group.ZeroScalar().SetReader(rand); err != nil {
			return nil, nil, err
		}

		// Calculate c_lj = Com_ck(l_j; r_j) = g^l_j * h^r_j
		if (opts.L & mask) != 0 { // if j-th bit of l value in binary is set (1)
			s1.SetOne() // 1
		} else { // if j-th bit of l value in binary is not set (0)
			s1.SetZero() // 0
		}
		E1.SetIdentity()
		if _, err = E1.Op(opts.G); err != nil { // g
			return nil, nil, err
		}
		E2.SetIdentity()
		if _, err = E2.Op(opts.H); err != nil { // h
			return nil, nil, err
		}
		if err = com_ck(E1, E2, s1, r_j[j-1]); err != nil { // g^l_j * h^r_j
			return nil, nil, err
		}
		commitments[j-1] = E1.Bytes() // c_lj

		// Calculate c_aj = Com_ck(a_j; s_j) = g^a_j * h^s_j
		E1.SetIdentity()
		if _, err = E1.Op(opts.G); err != nil { // g
			return nil, nil, err
		}
		E2.SetIdentity()
		if _, err = E2.Op(opts.H); err != nil { // h
			return nil, nil, err
		}
		if err = com_ck(E1, E2, a_j[j-1], s_j[j-1]); err != nil { // g^a_j * h^s_j
			return nil, nil, err
		}
		commitments[n+j-1] = E1.Bytes() // c_aj

		// Calculate c_bj = Com_ck(l_j*a_j; t_j) = g^(l_j*a_j) * h^t_j
		if (opts.L & mask) != 0 { // if j-th bit of l value in binary is set (1)
			s1.SetZero()
			if _, err = s1.Add(a_j[j-1]); err != nil { // a_j
				return nil, nil, err
			}
		} else { // if j-th bit of l value in binary is not set (0)
			s1.SetZero() // 0
		}
		E1.SetIdentity()
		if _, err = E1.Op(opts.G); err != nil { // g
			return nil, nil, err
		}
		E2.SetIdentity()
		if _, err = E2.Op(opts.H); err != nil { // h
			return nil, nil, err
		}
		if err = com_ck(E1, E2, s1, t_j[j-1]); err != nil { // g^(l_j*a_j) * h^t_j
			return nil, nil, err
		}
		commitments[n+n+j-1] = E1.Bytes() // c_bj
	}

	// Calculate simplified c_dk = Com_ck(d_k, ф_k + ρ_k). NB! In a membership proof ф_k = 0, so the equation
	// is therefore Com_ck(d_k, ρ_k)
	for i := range twoN { // (N-1)П(i=0)
		p_x[0].SetOne()
		for j := 1; j <= n; j++ {
			p_x[j].SetZero()
		}

		// Calculate p_x = (n)П(j=1)(f_j,i_j) = p_i,k + p_i,k+1 + ... + p_i,kn
		for j, mask := 1, 1; j <= n; j, mask = j+1, mask*2 {
			s2.SetZero()
			if (i & mask) != 0 { // if j-th bit of i is 1, i.e. f_j1 case
				if (opts.L & mask) != 0 { // l_j=1
					if err = polymul2(p_x, a_j[j-1], s2); err != nil {
						return nil, nil, err
					}
				} else { // l_j=0
					if err = polymul(p_x, a_j[j-1]); err != nil {
						return nil, nil, err
					}
				}
			} else { // if j-th bit of i is 0, i.e. f_j0 case
				s1.SetZero()
				if _, err = s1.Add(a_j[j-1]); err != nil { // a_j
					return nil, nil, err
				}

				s1.Negate()               // -a_j
				if (opts.L & mask) != 0 { // l_j=1
					if err = polymul(p_x, s1); err != nil {
						return nil, nil, err
					}
				} else { // l_j=0
					if err = polymul2(p_x, s1, s2); err != nil {
						return nil, nil, err
					}
				}
			}
		}

		// Calculate d(x) = (N-1)∑(i=0)(m_i*p_i(x)),
		// note that p_i(x) = p_i,k + p_i,k+1 + ... + p_i,kn, so m_i*p_i(x) actually means
		// m_i * (p_i,k + p_i,k+1 + ... + p_i,kn), i.e. multiply each polynomial coefficient p_i,k by a
		// scalar. NB! In a membership proof m_i = -m_i
		for k := range n {
			if i < N {
				if _, err = s2.SetBytes(opts.List[i]); err != nil { // value from a public list
					return nil, nil, err
				}
			} else {
				if _, err = s2.SetBytes(opts.List[0]); err != nil { // extend public list to 2^N values, duplicates are allowed
					return nil, nil, err
				}
			}

			if _, err = p_x[k].Mul(s2.Negate()); err != nil { // p_i,k * -m_i
				return nil, nil, err
			}
			if _, err = d_x[k].Add(p_x[k]); err != nil { // (N-1)∑(i=0)(m_i*p_i(x)), coefficient-wise summing
				return nil, nil, err
			}
		}
	}

	// Calculate Com_ck(d_k, ρ_k)
	for k := range n {
		E1.SetIdentity()
		if _, err = E1.Op(opts.G); err != nil { // g
			return nil, nil, err
		}
		E2.SetIdentity()
		if _, err = E2.Op(opts.H); err != nil { // h
			return nil, nil, err
		}
		if err = com_ck(E1, E2, d_x[k], p_k[k]); err != nil { // g^d_k * h^ρ_k
			return nil, nil, err
		}

		commitments[n+n+n+k] = E1.Bytes() // cd_k
	}

	return commitments, &ResponseOpts{
		Group: opts.Group,
		L:     opts.L,
		R:     opts.R,
		R_j:   r_j,
		A_j:   a_j,
		S_j:   s_j,
		T_j:   t_j,
		P_k:   p_k,
	}, nil
}

// Challenge uses PRNG-based Fiat-Shamir transformation to generate a challenge over provided data.
// Prefer strong Fiat-Shamir transformation over weak one.
func Challenge(r prng.Source, out []byte, data ...[]byte) error {
	return nizk.FiatShamirTransform(r, out, data...) // x ← {0,1}^λ
}

// ResponseOpts are mandatory options that define a response context.
type ResponseOpts struct {
	Group group.Group    // group to which all elements in this opts belong
	L     int            // index of a value from a public list
	R     []byte         // randomness used in a value commitment
	R_j   []group.Scalar // Sigma protocol randomness r_j
	A_j   []group.Scalar // Sigma protocol randomness a_j
	S_j   []group.Scalar // Sigma protocol randomness s_j
	T_j   []group.Scalar // Sigma protocol randomness t_j
	P_k   []group.Scalar // Sigma protocol randomness ρ_k
}

// Response is a prover response to the challenge.
func Response(challenge []byte, opts *ResponseOpts) ([][]byte, error) {
	if len(opts.R_j) != len(opts.A_j) &&
		len(opts.A_j) != len(opts.S_j) &&
		len(opts.S_j) != len(opts.T_j) &&
		len(opts.T_j) != len(opts.P_k) {
		return nil, errors.New("invalid randomness")
	}

	n := len(opts.R_j)

	response := make([][]byte, (n*3)+1) // {f_1, ..., f_n, z_a1, ..., z_an, z_b1, ..., z_bn, z_d}

	// These 3 variables below don't have special meaning and are just used as a temporary storage for
	// calculation results, pay attention to code comments as there are direct links to the algorithm
	s1 := opts.Group.ZeroScalar()
	s2 := opts.Group.ZeroScalar()
	s3 := opts.Group.ZeroScalar()

	var err error

	// For j = 1, ..., n
	for j, mask := 1, 1; j <= n; j, mask = j+1, mask*2 {
		// Calculate f_j = l_j*x + a_j
		if (opts.L & mask) != 0 { // l_j=1
			if _, err = s1.SetBytes(challenge); err != nil { // x
				return nil, err
			}
			if _, err = s1.Add(opts.A_j[j-1]); err != nil { // f_j = 1*x + a_j
				return nil, err
			}
			response[j-1] = s1.Bytes() // f_j
		} else { // l_j=0
			response[j-1] = opts.A_j[j-1].Bytes() // f_j = 0*x + a_j
		}
		if _, err = s2.SetBytes(response[j-1]); err != nil { // f_j
			return nil, err
		}

		// Calculate z_aj = r_j*x + s_j
		if _, err = s1.SetBytes(challenge); err != nil { // x
			return nil, err
		}
		if _, err = s1.Mul(opts.R_j[j-1]); err != nil { // r_j*x
			return nil, err
		}
		if _, err = s1.Add(opts.S_j[j-1]); err != nil { // r_j*x + s_j
			return nil, err
		}
		response[j-1+n] = s1.Bytes() // z_aj

		// Calculate z_bj = r_j*(x-f_j) + t_j
		if _, err = s1.SetBytes(challenge); err != nil { // x
			return nil, err
		}
		if _, err = s1.Sub(s2); err != nil { // x - f_j
			return nil, err
		}
		if _, err = s1.Mul(opts.R_j[j-1]); err != nil { // r_j*(x-f_j)
			return nil, err
		}
		if _, err = s1.Add(opts.T_j[j-1]); err != nil { // r_j*(x-f_j) + t_j
			return nil, err
		}
		response[j-1+n+n] = s1.Bytes() // z_bj
	}

	s2.SetOne()
	s3.SetZero()

	// Calculate (n-1)Σ(k=0)(ρ_k * x^k)
	for k := range n {
		s1.SetZero()
		if _, err = s1.Add(opts.P_k[k]); err != nil { // ρ_k
			return nil, err
		}
		if _, err = s1.Mul(s2); err != nil { // ρ_k * x^k
			return nil, err
		}
		if _, err = s3.Add(s1); err != nil { // (n-1)Σ(k=0)(ρ_k * x^k)
			return nil, err
		}
		if _, err = s1.SetBytes(challenge); err != nil { // x
			return nil, err
		}
		if _, err = s2.Mul(s1); err != nil { // x^k = x*x*x...
			return nil, err
		}
	}

	// Calculate z_d = (r * x^n) - (n-1)Σ(k=0)(ρ_k * x^k)
	if _, err = s1.SetBytes(opts.R); err != nil { // r
		return nil, err
	}
	if _, err = s2.Mul(s1); err != nil { // r * x^n
		return nil, err
	}
	if _, err = s2.Sub(s3); err != nil { // (r * x^n) - (n-1)Σ(k=0)(ρ_k * x^k)
		return nil, err
	}
	response[len(response)-1] = s2.Bytes() // z_d

	return response, nil
}

// VerifyOpts are mandatory options that define a verifier context.
type VerifyOpts struct {
	Group      group.Group   // group to which all elements in this opts belong
	G          group.Element // g param of a commitment key ck (g,h), which is used in Com_ck
	H          group.Element // h param of a commitment key ck (g,h), which is used in Com_ck
	List       [][]byte      // public list {λ_1, ..., λ_N}
	Commitment []byte        // prover's commitment of a value from a public list
}

// Verify verifies that prover knows an index l of a value from a public list.
func Verify(commitment [][]byte, challenge []byte, response [][]byte, opts *VerifyOpts) error {
	N := len(opts.List)
	n := 1
	twoN := 2 // 2^n
	for ; twoN < N; n++ {
		twoN <<= 1
	}

	if len(commitment) != n*4 || len(response) != (n*3)+1 {
		return errors.New("invalid proof")
	}

	// These 7 variables below don't have special meaning and are just used as temporary storage for
	// calculation results, pay attention to code comments as there are direct links to the algorithm
	E1 := opts.Group.Identity()
	E2 := opts.Group.Identity()
	E3 := opts.Group.Identity()
	s1 := opts.Group.ZeroScalar()
	s2 := opts.Group.ZeroScalar()
	s3 := opts.Group.ZeroScalar()
	s4 := opts.Group.ZeroScalar()

	var err error

	// For all j∈{1, ..., n}
	for j := 1; j <= n; j++ {
		// Calculate c_lj^x * c_aj = Com_ck(f_j; z_aj)
		if _, err = E1.SetBytes(commitment[j-1]); err != nil { // c_lj
			return err
		}
		if _, err = s1.SetBytes(challenge); err != nil { // x
			return err
		}
		if _, err = E1.Scale(s1); err != nil { // c_lj^x
			return err
		}
		if _, err = E2.SetBytes(commitment[n+(j-1)]); err != nil { // c_aj
			return err
		}
		if _, err = E1.Op(E2); err != nil { // c_lj^x * c_aj
			return err
		}
		E2.SetIdentity()
		if _, err = E2.Op(opts.G); err != nil { // g
			return err
		}
		E3.SetIdentity()
		if _, err = E3.Op(opts.H); err != nil { // h
			return err
		}
		if _, err = s1.SetBytes(response[j-1]); err != nil { // f_j
			return err
		}
		if _, err = s2.SetBytes(response[n+(j-1)]); err != nil { // z_aj
			return err
		}
		if err = com_ck(E2, E3, s1, s2); err != nil { // g^f_j * h^z_aj
			return err
		}
		if err = E1.Equal(E2); err != nil { // c_lj^x * c_aj = g^f_j * h^z_aj
			return errors.New("verification step 1 failed")
		}

		// Calculate c_lj^(x-f_j) * c_bj = Com_ck(0; z_bj)
		if _, err = E1.SetBytes(commitment[j-1]); err != nil { // c_lj
			return err
		}
		if _, err = s1.SetBytes(challenge); err != nil { // x
			return err
		}
		if _, err = s2.SetBytes(response[j-1]); err != nil { // f_j
			return err
		}
		if _, err = s1.Sub(s2); err != nil { // x - f_j
			return err
		}
		if _, err = E1.Scale(s1); err != nil { // c_lj^(x - f_j)
			return err
		}
		if _, err = E2.SetBytes(commitment[(n*2)+(j-1)]); err != nil { // c_bj
			return err
		}
		if _, err = E1.Op(E2); err != nil { // cl_j^(x - f_j) * c_bj
			return err
		}
		E2.SetIdentity()
		if _, err = E2.Op(opts.G); err != nil { // g
			return err
		}
		E3.SetIdentity()
		if _, err = E3.Op(opts.H); err != nil { // h
			return err
		}
		s1.SetZero()
		if _, err = s2.SetBytes(response[(n*2)+(j-1)]); err != nil { // z_bj
			return err
		}
		if err = com_ck(E2, E3, s1, s2); err != nil { // g^0 * h^z_bj
			return err
		}
		if err = E1.Equal(E2); err != nil { // c_lj^(x - f_j) * c_bj = g^0 * h^z_bj
			return errors.New("verification step 2 failed")
		}
	}

	E3.SetIdentity()

	// Calculate (N-1)П(i=0)(c_i^((n)П(j=1)(f_j*i_j))), which in case of a
	// membership proof can be simplified to c^(x^n) * Com_ck(-(N-1)Σ(i=0)(λ_i*p_i(x); 0)),
	// where p_i(x) = (n)П(j=1)(f_j*i_j)
	for i := range twoN { // (N-1)П(i=0)
		s2.SetOne()

		// Calculate p_i(x) = (n)П(j=1)(f_j*i_j)
		for j, mask := 1, 1; j <= n; j, mask = j+1, mask*2 {
			s1.SetZero()
			if (i & mask) != 0 { // f_j1
				if _, err = s1.SetBytes(response[j-1]); err != nil { // f_j
					return err
				}
			} else { // f_j0
				if _, err = s1.SetBytes(challenge); err != nil { // x
					return err
				}
				if _, err = s3.SetBytes(response[j-1]); err != nil { // f_j
					return err
				}
				if _, err = s1.Sub(s3); err != nil { // x - f_j
					return err
				}
			}
			if _, err = s2.Mul(s1); err != nil { // (n)П(j=1)(f_j*i_j)
				return err
			}
		}

		// Calculate (N-1)Σ(i=0)(λ_i*p_i(x))
		if i < N {
			if _, err = s1.SetBytes(opts.List[i]); err != nil { // λ_i
				return err
			}
		} else {
			// NB! Duplicates are allowed but must be the same as prover uses in Commit
			if _, err = s1.SetBytes(opts.List[0]); err != nil { // λ_0, pad the public list to N-1 size
				return err
			}
		}
		if _, err = s1.Mul(s2); err != nil { // λ_i*p_i(x)
			return err
		}
		if _, err = s4.Add(s1); err != nil { // (N-1)Σ(i=0)(λ_i*p_i(x))
			return err
		}
	}

	s2.SetZero()
	E2.SetIdentity()
	if _, err = E2.Op(opts.G); err != nil { // g
		return err
	}
	E1.SetIdentity()
	if _, err = E1.Op(opts.H); err != nil { // h
		return err
	}
	if err = com_ck(E2, E1, s4.Negate(), s2); err != nil { // Com_ck(-(N-1)Σ(i=0)(λ_i*p_i(x); 0))
		return err
	}

	if _, err = s3.SetBytes([]byte{uint8(n)}); err != nil { //nolint:gosec // n
		return err
	}
	if _, err = s2.SetBytes(challenge); err != nil { // x
		return err
	}
	if _, err = s2.Exp(s3); err != nil { // x^n
		return err
	}
	if _, err = E3.SetBytes(opts.Commitment); err != nil { // c
		return err
	}
	if _, err = E3.Scale(s2); err != nil { // c^(x^n)
		return err
	}
	if _, err = E3.Op(E2); err != nil { // c^(x^n) * Com_ck(-(N-1)Σ(i=0)(λ_i*p_i(x); 0))
		return err
	}

	// Calculate Com_ck(0; z_d), i.e. g^0 * h^z_d
	s2.SetZero() // 0

	E2.SetIdentity()
	if _, err = E2.Op(opts.G); err != nil { // g
		return err
	}
	E1.SetIdentity()
	if _, err = E1.Op(opts.H); err != nil { // h
		return err
	}
	if _, err = s1.SetBytes(response[len(response)-1]); err != nil { // z_d
		return err
	}
	if err = com_ck(E2, E1, s2, s1); err != nil { // Com_ck(0; z_d)
		return err
	}

	// This variable will hold a value of x^k
	s1.SetOne() // start with k=0, i.e. x^0 = 1

	// Calculate (n-1)П(k=0)(cd_k^(-x^k))
	for k := range n {
		if _, err = E1.SetBytes(commitment[(n*3)+k]); err != nil { // cd_k
			return err
		}
		if _, err = E1.Scale(s1.Negate()); err != nil { // cd_k^(-x^k)
			return err
		}
		s1.Negate()                         // negate back to restore a value of x^k
		if _, err = E3.Op(E1); err != nil { // (N-1)П(i=0) * cd_k^(-x^k)
			return err
		}
		if _, err = s2.SetBytes(challenge); err != nil { // x
			return err
		}
		if _, err = s1.Mul(s2); err != nil { // x^k = x*x*x...
			return err
		}
	}
	if err = E3.Equal(E2); err != nil { // c^(x^n) * Com_ck(-(N-1)Σ(i=0)(λ_i*p_i(x); 0)) * (n-1)П(k=0)(cd_k^(-x^k)) = Com_ck(0; z_d)
		return errors.New("verification step 3 failed")
	}

	return nil
}

// com_ck sets h = h^r and then sets g to the result of a Pedersen commitment g = g^m * h^r,
// where m is a message to be committed and r is perhaps a randomness.
// See also "2.1 Homomorphic commitment schemes".
func com_ck(g, h group.Element, m, r group.Scalar) error {
	if _, err := g.Scale(m); err != nil { // g^m
		return err
	}
	if _, err := h.Scale(r); err != nil { // h^r
		return err
	}
	if _, err := g.Op(h); err != nil { // g^m * h^r
		return err
	}

	return nil
}

// polymul multiplies polynomial coefficients by a scalar s.
func polymul(poly []group.Scalar, s group.Scalar) error {
	for i := range poly { // given polynomial a + b + c
		if _, err := poly[i].Mul(s); err != nil { // as + bs+ cs
			return err
		}
	}

	return nil
}

// polymul2 does following, suppose given a polynomial a + b + c perform steps below:
//  1. Multiply by scalar s as follows as + bs + c
//  2. Add previous coefficient as follows (as+b) + (bs+c) + c
//  3. Multiply polynomial constant by scalar s as follows (as+b) + (bs+c) + cs
func polymul2(poly []group.Scalar, s, zeroC group.Scalar) error {
	if poly[len(poly)-1].Equal(zeroC) != nil {
		return errors.New("invalid polynomial degree")
	}

	for i := len(poly) - 1; i > 0; i-- { // given polynomial a + b + c
		if _, err := poly[i].Mul(s); err != nil { // as + bs + c
			return err
		}
		if _, err := poly[i].Add(poly[i-1]); err != nil { // (as+b) + (bs+c) + c
			return err
		}
	}
	if _, err := poly[0].Mul(s); err != nil { // (as+b) + (bs+c) + cs
		return err
	}

	return nil
}
