package main

import (
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
	if *quick {
		return
	}
	if max_version == 0 {
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
