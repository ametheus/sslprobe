package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
)

func main() {
	message := []byte("MODULUS")
	message_p := []byte("PRIME Pea")
	pb := make([]byte, 32)
	pb[0] = 0x80
	for i, c := range message {
		pb[i] |= c >> 7
		pb[i+1] |= c << 1
	}
	copy(pb[len(message)+2:], message_p)
	p, err := PrimeWithPrefix(pb, 512)
	if err != nil {
		panic(err)
	}

	qb := make([]byte, 33)
	message_q := []byte("PRIME Queue")
	qb[0] = 0x80
	copy(qb[len(message)+2:], message_q)
	q, err := PrimeWithPrefix(qb, 512)
	if err != nil {
		panic(err)
	}

	n := big.NewInt(0)
	n.Mul(p, q)

	// To calculate the modulus from the desired private key, we need simply to
	// invert it modulo (p-1)(q-1)
	phi_p := big.NewInt(-1)
	phi_p.Add(phi_p, p)
	phi_q := big.NewInt(-1)
	phi_q.Add(phi_q, q)
	phi := big.NewInt(0)
	phi.Mul(phi_p, phi_q)

	d := big.NewInt(0x10001)
	d.ModInverse(d, phi)

	private := new(rsa.PrivateKey)
	private.N = n
	private.E = 0x10001
	private.D = d
	private.Primes = []*big.Int{p, q}
	private.Precompute()

	rfckey := rfc3441PrivateKey{Version: 0,
		Modulus:         n,
		PublicExponent:  0x10001,
		PrivateExponent: d,
		Prime1:          p, Prime2: q,
		Exponent1:   private.Precomputed.Dp,
		Exponent2:   private.Precomputed.Dq,
		Coefficient: private.Precomputed.Qinv}

	priv_enc, err := asn1.Marshal(rfckey)
	if err != nil {
		panic(err)
	}

	b := pem.Block{Type: "RSA PRIVATE KEY", Bytes: priv_enc}
	pem.Encode(os.Stdout, &b)
}

type rfc3441PrivateKey struct {
	Version              int
	Modulus              *big.Int // n
	PublicExponent       int      // e
	PrivateExponent      *big.Int // d
	Prime1, Prime2       *big.Int // p, q
	Exponent1, Exponent2 *big.Int // d mod (p-1), d mod (q-1)
	Coefficient          *big.Int // (inverse of q) mod p
}

// smallPrimes is a list of small, prime numbers that allows us to rapidly
// exclude some fraction of composite candidates when searching for a random
// prime. This list is truncated at the point where smallPrimesProduct exceeds
// a uint64. It does not include two because we ensure that the candidates are
// odd by construction.
var smallPrimes = []uint8{
	3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
}

// smallPrimesProduct is the product of the values in smallPrimes and allows us
// to reduce a candidate prime by this number and then determine whether it's
// coprime to all the elements of smallPrimes without further big.Int
// operations.
var smallPrimesProduct = new(big.Int).SetUint64(16294579238595022365)

// Prime returns a number, p, of the given size, such that p is prime
// with high probability.
// Prime will return error for any error returned by rand.Read or if bits < 2.
func PrimeWithPrefix(prefix []byte, bits int) (p *big.Int, err error) {
	if bits < 2 {
		err = errors.New("crypto/rand: prime size must be at least 2-bit")
		return
	}

	b := uint(bits % 8)
	if b == 0 {
		b = 8
	} else {
		return nil, errors.New("I don't know how to deal with non-multiples of 8")
	}
	c := 0

	bytes := make([]byte, (bits+7)/8)
	copy(bytes, prefix)
	p = new(big.Int)

	bigMod := new(big.Int)

	for {
		_, err = rand.Read(bytes[len(prefix):])
		if err != nil {
			return nil, err
		}

		// Make the value odd since an even number this large certainly isn't prime.
		bytes[len(bytes)-1] |= 1

		p.SetBytes(bytes)

		// Calculate the value mod the product of smallPrimes.  If it's
		// a multiple of any of these primes we add two until it isn't.
		// The probability of overflowing is minimal and can be ignored
		// because we still perform Miller-Rabin tests on the result.
		bigMod.Mod(p, smallPrimesProduct)
		mod := bigMod.Uint64()

	NextDelta:
		for delta := uint64(0); delta < 1<<20; delta += 2 {
			m := mod + delta
			for _, prime := range smallPrimes {
				if m%uint64(prime) == 0 && (bits > 6 || m != uint64(prime)) {
					continue NextDelta
				}
			}

			if delta > 0 {
				bigMod.SetUint64(delta)
				p.Add(p, bigMod)
			}
			break
		}

		// There is a tiny possibility that, by adding delta, we caused
		// the number to be one bit too long. Thus we check BitLen
		// here.
		if p.ProbablyPrime(20) && p.BitLen() == bits {
			return
		}
		c++
	}
}
