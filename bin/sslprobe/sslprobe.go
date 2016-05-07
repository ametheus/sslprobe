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

	fmt.Printf("Server:   %s\n", tc.Bblue(fmt.Sprintf("%s:%d", host, port)))

	found := false
	versions := sslprobe.SupportedProtocols(host, port)
	fmt.Printf("Protocol support:")
	for _, sv := range versions {
		v, s := sv.Version, sv.Supported
		var col func(string) string = nil
		if s {
			found = true
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
	fmt.Printf("\n\n")
	if !found {
		return
	}

	fmt.Printf("Cipher suites, in server-preferred order:\n")
	for _, sv := range versions {
		if sv.Supported {
			fmt.Printf("  %s\n", sv.Version)
			prefs := sslprobe.CipherPreference(host, port, sv.Version)
			for _, c := range prefs {
				fmt.Printf("     %s\n", c.Name)
			}
		}
	}
}
