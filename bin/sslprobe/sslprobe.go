package main

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"flag"
	"fmt"
	tc "github.com/thijzert/go-termcolours"
	"github.com/thijzert/sslprobe"
	"os"
)

var (
	port = flag.Int("port", 443, "Connect to this port")

	full  = flag.Bool("full", false, "Perform cipher and curve preference tests on every supported version rather than just the highest")
	quick = flag.Bool("quick", false, "Just test for protocol version support and exit early")

	full_a  = flag.Bool("f", false, "Alias for --full")
	quick_a = flag.Bool("q", false, "Alias for --quick")
	port_a  = flag.Int("p", 443, "Alias for --port")

	just_ssl2  = flag.Bool("ssl2", false, "Just use SSLv2 (experimental)")
	just_ssl3  = flag.Bool("ssl3", false, "Just use SSLv3")
	just_tls10 = flag.Bool("tls10", false, "Just use TLSv1.0")
	just_tls11 = flag.Bool("tls11", false, "Just use TLSv1.1")
	just_tls12 = flag.Bool("tls12", false, "Just use TLSv1.2")
	just_tls13 = flag.Bool("tls13", false, "Just use TLSv1.3 (experimental)")
)

func init() {
	flag.Parse()
	if *quick_a {
		*quick = true
	}
	if *full_a {
		*full = true
	}
	if *full {
		*quick = false
	}

	if *just_tls13 {
		sslprobe.AllVersions = []sslprobe.TLSVersion{sslprobe.TLS_1_3}
	} else if *just_tls12 {
		sslprobe.AllVersions = []sslprobe.TLSVersion{sslprobe.TLS_1_2}
	} else if *just_tls11 {
		sslprobe.AllVersions = []sslprobe.TLSVersion{sslprobe.TLS_1_1}
	} else if *just_tls10 {
		sslprobe.AllVersions = []sslprobe.TLSVersion{sslprobe.TLS_1_0}
	} else if *just_ssl3 {
		sslprobe.AllVersions = []sslprobe.TLSVersion{sslprobe.SSL_3_0}
	} else if *just_ssl2 {
		sslprobe.AllVersions = []sslprobe.TLSVersion{sslprobe.SSL_2_0}
	}

	if *port == 443 && *port_a != 443 {
		*port = *port_a
	}
}

func main() {
	if flag.NArg() == 0 {
		fmt.Fprintf(os.Stderr, "Usage: %s {HOST} [{OPTIONS}]\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	var col func(string) string = nil

	host := flag.Arg(0)
	fmt.Printf("Server:   %s\n", tc.Bblue(fmt.Sprintf("%s:%d", host, *port)))

	probe := sslprobe.New(host, *port)

	var max_version sslprobe.TLSVersion = 0
	fmt.Printf("Protocol support:")
	for _, sv := range probe.SupportedVersions {
		if sv.Supported {
			max_version = sv.Version
		}
		fmt.Printf("  %s", sv.Pretty())
	}
	fmt.Printf("\n")
	if max_version == 0 {
		return
	}

	// Print certificate chain(s)
	for i, _ := range probe.SupportedVersions {
		sv := &probe.SupportedVersions[len(probe.SupportedVersions)-i-1]
		if !*full && sv.Version != max_version {
			continue
		}
		if !sv.Supported || sv.CertificateChain == nil {
			continue
		}

		fmt.Printf("\nCertificate chain:\n")
		for i, b := range sv.CertificateChain {
			cert, err := x509.ParseCertificate(b)
			if err != nil {
				fmt.Printf("   %2d %s: %s\n", i, tc.Red("error"), err)
				continue
			}
			subj, iss := prettyCertificate(cert)
			fmt.Printf("   %2d %s\n      %s\n", i, subj, iss)
		}
	}

	if *quick {
		return
	}

	fmt.Printf("\nCipher suites, in server-preferred order:\n")
	var cipher_prefs []sslprobe.CipherInfo = []sslprobe.CipherInfo{}
	for i, _ := range probe.SupportedVersions {
		sv := &probe.SupportedVersions[len(probe.SupportedVersions)-i-1]
		if !*full && sv.Version != max_version {
			continue
		}
		if sv.Supported {
			probe.FillDetails(sv.Version)

			if len(cipher_prefs) == 0 {
				cipher_prefs = sv.SupportedCiphers
			}
			fmt.Printf("  %s\n", sv.Version)
			for _, c := range sv.SupportedCiphers {
				fmt.Printf("     %s\n", c.Pretty())
			}
		}
	}

	// Loop over the highest protocol version's ciphers again and figure out if
	// there's any useful information in the ServerKeyExchange
	for i, _ := range probe.SupportedVersions {
		sv := probe.SupportedVersions[len(probe.SupportedVersions)-i-1]
		if !sv.Supported {
			continue
		}

		if sv.FFDHSize > 0 || len(sv.SupportedCurves) > 0 {
			fmt.Printf("\nEphemeral Key Exchange strength\n")

			if sv.FFDHSize > 0 {
				col = cStrength(sv.FFDHSize)
				fmt.Printf("   DH Modulus size: %5s bits\n", col(fmt.Sprintf("%d", sv.FFDHSize)))
			}
			if len(sv.SupportedCurves) == 1 {
				curve := sv.SupportedCurves[0]
				dlen := curve.DHBits()
				col = cStrength(dlen)
				fmt.Printf("   Preferred Curve: %s (%d bits, eq %s bits DH)\n", col(curve.Name), curve.Bits, col(fmt.Sprintf("%d", dlen)))
			} else if len(sv.SupportedCurves) > 1 {
				fmt.Printf("   Supported elliptic curves:\n")
				for _, curve := range sv.SupportedCurves {
					dlen := curve.DHBits()
					col = cStrength(dlen)
					fmt.Printf("        %s (%d bits, eq %s bits DH)\n", col(curve.Name), curve.Bits, col(fmt.Sprintf("%d", dlen)))
				}
			}
		}

		break
	}

	probe.OtherChecks()

	if probe.Results != nil {
		fmt.Printf("\nOther scan results:\n")
		for _, result := range probe.Results {
			c := cSeverity(result.Severity)
			fmt.Printf("   %-25s :  %s\n", result.Label, c(result.Result))
		}
	}
}

func cSeverity(s sslprobe.Severity) func(string) string {
	if s == sslprobe.Bonus {
		return tc.Green
	} else if s == sslprobe.OK {
		return tc.Bblack
	} else if s == sslprobe.Bad {
		return tc.Red
	} else if s == sslprobe.BigFuckingProblem {
		return tc.Bred
	} else {
		return func(s string) string {
			return s
		}
	}
}

func cStrength(bits int) func(string) string {
	if bits > 2048 {
		return tc.Green
	} else if bits > 1536 {
		return tc.Yellow
	} else if bits > 1024 {
		return tc.Red
	} else {
		return tc.Bred
	}
}

func prettyCertificate(cert *x509.Certificate) (string, string) {
	key := "unknown"
	if cert.PublicKeyAlgorithm == x509.RSA {
		pk, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			key = tc.Bred("RSA - error")
		} else {
			col := cStrength(pk.N.BitLen())
			key = col(fmt.Sprintf("RSA-%d", pk.N.BitLen()))
		}
	} else if cert.PublicKeyAlgorithm == x509.DSA {
		pk, ok := cert.PublicKey.(*dsa.PublicKey)
		if !ok {
			key = tc.Bred("DSA - error")
		} else {
			bl := pk.P.BitLen()
			col := tc.Red
			if bl < 1536 {
				col = tc.Bred
			}
			key = col(fmt.Sprintf("DSA-%d", bl))
		}
	} else if cert.PublicKeyAlgorithm == x509.ECDSA {
		pk, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			key = tc.Bred("ECDSA - error")
		} else {
			bl := pk.Params().P.BitLen()
			col := tc.Green
			if bl < 224 {
				col = tc.Red
			} else if bl < 256 {
				col = tc.Yellow
			}
			key = col(fmt.Sprintf("ECDSA-%d", bl))
		}
	}

	sig := strSigAlg(cert.SignatureAlgorithm)
	if cert.SignatureAlgorithm == x509.UnknownSignatureAlgorithm ||
		cert.SignatureAlgorithm == x509.MD2WithRSA ||
		cert.SignatureAlgorithm == x509.MD5WithRSA {
		sig = tc.Bred(sig)
	} else if cert.SignatureAlgorithm == x509.SHA1WithRSA ||
		cert.SignatureAlgorithm == x509.DSAWithSHA1 ||
		cert.SignatureAlgorithm == x509.DSAWithSHA256 ||
		cert.SignatureAlgorithm == x509.ECDSAWithSHA1 {
		sig = tc.Red(sig)
	} else {
		sig = tc.Green(sig)
	}

	subject := cert.Subject.CommonName
	if len(subject) > 45 {
		subject = subject[0:45]
	}
	issuer := cert.Issuer.CommonName
	if len(issuer) > 45 {
		issuer = issuer[0:45]
	}

	fpr := tc.Bblack(fmt.Sprintf("%x", sha1.Sum(cert.Raw)))

	subject = fmt.Sprintf("subject: %-45s  key type: %s / sig: %s", subject, key, sig)
	issuer = fmt.Sprintf("issuer:  %-45s  fingerprint: %s", issuer, fpr)

	return subject, issuer
}

func strSigAlg(s x509.SignatureAlgorithm) string {
	if s == x509.MD2WithRSA {
		return "MD2-RSA"
	} else if s == x509.MD5WithRSA {
		return "MD5-RSA"
	} else if s == x509.SHA1WithRSA {
		return "SHA1-RSA"
	} else if s == x509.SHA256WithRSA {
		return "SHA256-RSA"
	} else if s == x509.SHA384WithRSA {
		return "SHA384-RSA"
	} else if s == x509.SHA512WithRSA {
		return "SHA512-RSA"
	} else if s == x509.DSAWithSHA1 {
		return "SHA1-DSA"
	} else if s == x509.DSAWithSHA256 {
		return "SHA256-DSA"
	} else if s == x509.ECDSAWithSHA1 {
		return "SHA1-ECDSA"
	} else if s == x509.ECDSAWithSHA256 {
		return "SHA256-ECDSA"
	} else if s == x509.ECDSAWithSHA384 {
		return "SHA384-ECDSA"
	} else if s == x509.ECDSAWithSHA512 {
		return "SHA512-ECDSA"
	}
	return "UnknownSignatureAlgorithm"
}
