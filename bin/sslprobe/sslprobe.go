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
	versions := probe.SupportedProtocols()
	fmt.Printf("Protocol support:")
	for _, sv := range versions {
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
	for _, sv := range versions {
		if sv.Supported {
			fmt.Printf("  %s\n", sv.Version)
			cipher_prefs = probe.CipherPreference(sv.Version)
			for _, c := range cipher_prefs {
				fmt.Printf("     %s\n", FCipher(c))
			}
		}
	}

	// Loop over the highest protocol version's ciphers again and figure out if
	// there's any useful information in the ServerKeyExchange
	f_ffdhe := sslprobe.TLS_NULL
	f_ecdhe := sslprobe.TLS_NULL
	for _, c := range cipher_prefs {
		if c.Kex == sslprobe.KX_FFDHE && f_ffdhe.ID == 0 {
			f_ffdhe = c
		} else if c.Kex == sslprobe.KX_ECDHE && f_ecdhe.ID == 0 {
			f_ecdhe = c
		}
	}
	if f_ffdhe.ID != 0 || f_ecdhe.ID != 0 {
		fmt.Printf("\nEphemeral Key Exchange strength\n")
		if f_ffdhe.ID != 0 {
			_, _, serverKeyExchange, err := probe.HalfHandshake(max_version, []sslprobe.CipherInfo{f_ffdhe})
			if err != nil {
				panic(err)
			}
			if serverKeyExchange != nil {
				dh_len := int(serverKeyExchange[0])<<8 | int(serverKeyExchange[1])
				col = cStrength(dh_len * 8)
				fmt.Printf("DH Modulus size: %5s bits\n", col(fmt.Sprintf("%d", dh_len*8)))
			}
		}
		if f_ecdhe.ID != 0 {
			_, _, serverKeyExchange, err := probe.HalfHandshake(max_version, []sslprobe.CipherInfo{f_ecdhe})
			if err != nil {
				panic(err)
			}
			if serverKeyExchange != nil {
				if serverKeyExchange[0] == 3 {
					// Named Curve - whew!
					id := uint16(serverKeyExchange[1])<<8 | uint16(serverKeyExchange[2])
					curve := sslprobe.IDCurve(id)
					dlen := curve.DHBits()
					col = cStrength(dlen)
					fmt.Printf("Preferred Curve: %s (%d bits, eq %s bits DH)\n", col(curve.Name), curve.Bits, col(fmt.Sprintf("%d", dlen)))
				} else {
					panic("Don't quite know how to handle this curve encoding")
				}
			}
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
