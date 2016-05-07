package main

import (
	"fmt"
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

	prefs := sslprobe.CipherPreference(host, port, sslprobe.TLS_1_2)
	if len(prefs) > 0 {
		fmt.Printf("Cipher suites, in server-preferred order:\n")
		for _, c := range prefs {
			fmt.Printf("   %s\n", c.Name)
		}
	}
}
