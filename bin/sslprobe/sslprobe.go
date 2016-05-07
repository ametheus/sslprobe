package main

import (
	"fmt"
	tc "github.com/ametheus/go-termcolours"
	"github.com/ametheus/sslprobe"
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

	var max_version sslprobe.TLSVersion = 0
	versions := sslprobe.SupportedProtocols(host, port)
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
			cipher_prefs = sslprobe.CipherPreference(host, port, sv.Version)
			for _, c := range cipher_prefs {
				fmt.Printf("     %s\n", c.Name)
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
			_, _, serverKeyExchange, err := sslprobe.HalfHandshake(host, port, max_version, []sslprobe.CipherInfo{f_ffdhe})
			if err != nil {
				panic(err)
			}
			if serverKeyExchange != nil {
				dh_len := int(serverKeyExchange[0])<<8 | int(serverKeyExchange[1])
				col = tc.Bred
				if dh_len*8 > 2048 {
					col = tc.Green
				} else if dh_len*8 > 1536 {
					col = tc.Yellow
				} else if dh_len*8 > 1024 {
					col = tc.Red
				}
				fmt.Printf("DH Modulus size: %5s bits\n", col(fmt.Sprintf("%d", dh_len*8)))
			}
		}
	}
}
