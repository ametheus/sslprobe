package main

import (
	"fmt"
	tc "github.com/thijzert/go-termcolours"
	"github.com/thijzert/sslprobe"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s {HOST} [{PORT}]\n", os.Args[0])
		os.Exit(1)
	}

	host := os.Args[1]
	port := 443
	if len(os.Args) > 2 {
		fmt.Sscanf(os.Args[2], "%d", &port)
	}
	var col func(string) string = nil

	fmt.Printf("Server:   %s\n", tc.Bblue(fmt.Sprintf("%s:%d", host, port)))

	probe := sslprobe.New(host, port)

	var max_version sslprobe.TLSVersion = 0
	fmt.Printf("Protocol support:")
	for _, sv := range probe.SupportedVersions {
		col = nil
		v, s := sv.Version, sv.Supported
		if s {
			max_version = v
			if v == sslprobe.SSL_2_0 {
				col = tc.Bred
			} else if v == sslprobe.SSL_3_0 {
				col = tc.Red
			} else if v == sslprobe.TLS_1_2 || v == sslprobe.TLS_1_3 {
				col = tc.Bgreen
			} else {
				col = tc.Green
			}
		} else {
			if v != sslprobe.SSL_2_0 && v != sslprobe.TLS_1_3 {
				col = tc.Bblack
			}
		}

		if col != nil {
			fmt.Printf("  %s", col(v.String()))
		}
	}
	fmt.Printf("\n")
	if max_version == 0 {
		return
	}

	fmt.Printf("\nCipher suites, in server-preferred order:\n")
	var cipher_prefs []sslprobe.CipherInfo = []sslprobe.CipherInfo{}
	for i, _ := range probe.SupportedVersions {
		sv := probe.SupportedVersions[len(probe.SupportedVersions)-i-1]
		if sv.Supported {
			if len(cipher_prefs) == 0 {
				cipher_prefs = sv.SupportedCiphers
			}
			fmt.Printf("  %s\n", sv.Version)
			for _, c := range sv.SupportedCiphers {
				fmt.Printf("     %s\n", FCipher(c))
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
			if len(sv.SupportedCurves) > 0 {
				// TODO: probe and display all supported curves, in order of preference.
				curve := sv.SupportedCurves[0]
				dlen := curve.DHBits()
				col = cStrength(dlen)
				fmt.Printf("   Preferred Curve: %s (%d bits, eq %s bits DH)\n", col(curve.Name), curve.Bits, col(fmt.Sprintf("%d", dlen)))
			}
		}

		break
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

func FCipher(c sslprobe.CipherInfo) string {
	var colour func(string) string = nil
	suffix := ""
	if c.Kex.Broken || c.Auth.Broken || c.Cipher.Broken || c.MAC.Broken {
		colour = tc.Red
		suffix = colour("  INSECURE")
	} else if c.Cipher.KeySize < 112 || c.MAC.TagSize < 160 {
		colour = tc.Yellow
		suffix = colour("  WEAK")
	}
	pad := "                                              "

	fs := tc.Yellow("no FS")
	if c.Kex.ForwardSecure {
		fs = tc.Green("  FS ")
	}

	aead := "    "
	if c.MAC.AEAD {
		aead = "AEAD"
	}

	cstr := fmt.Sprintf("%3d", c.Cipher.KeySize)
	if colour == nil && c.Kex.ForwardSecure && c.Cipher.KeySize >= 128 && c.MAC.AEAD {
		cstr = tc.Green(cstr)
		aead = tc.Green(aead)
	}

	if colour == nil {
		colour = func(s string) string {
			return s
		}
	}

	return fmt.Sprintf("%s%s  %s %s %s%s", colour(c.Name), pad[len(c.Name)%46:], fs, cstr, aead, suffix)
}
