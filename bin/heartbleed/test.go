package main

import (
	"flag"
	"fmt"
	tc "github.com/thijzert/go-termcolours"
	hex "github.com/thijzert/sslprobe/hexdump"
	"github.com/thijzert/sslprobe/ssltvd"
	"os"
)

var (
	port = flag.Int("port", 443, "Connect to this port")
)

func init() {
	flag.Parse()
}

func main() {
	if flag.NArg() == 0 {
		fmt.Fprintf(os.Stderr, "Usage: %s {HOST} [{OPTIONS}]\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(1)
	}

	host := flag.Arg(0)
	fmt.Printf("Server:   %s\n", tc.Bblue(fmt.Sprintf("%s:%d", host, *port)))

	c, err := ssltvd.Dial("tcp", fmt.Sprintf("%s:%d", host, *port), &ssltvd.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		panic(err)
	}

	pl, err := c.Heartbeat(6, []byte("potato"))
	if err != nil {
		panic(err)
	}
	hex.Dump(pl)

	pl, err = c.Heartbeat(4, []byte("bird"))
	if err != nil {
		panic(err)
	}
	hex.Dump(pl)

	pl, err = c.Heartbeat(1000, []byte("hat"))
	if err != nil {
		panic(err)
	}
	hex.Dump(pl)
}
