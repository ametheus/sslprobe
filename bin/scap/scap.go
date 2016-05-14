package main

import (
	"fmt"
	hex "github.com/thijzert/sslprobe/hexdump"
	"io"
	"net"
	"os"
	"sync"
)

var listen int

var host string
var port int

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s {LISTEN_PORT} {HOST} [{PORT}]\n", os.Args[0])
		os.Exit(1)
	}

	listen = 0
	fmt.Sscanf(os.Args[1], "%d", &listen)
	host = os.Args[2]
	port = 443
	if len(os.Args) > 3 {
		fmt.Sscanf(os.Args[3], "%d", &port)
	}

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", listen))
	if err != nil {
		panic(err)
	}

	fmt.Printf("Listening on port %d\n", listen)
	fmt.Printf("Passing through to:    %s:%d\n", host, port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			panic(err)
		}

		// Do this synchronously in order to only write one session to stdout at a time.
		// TODO: write each session to a different file.
		err = session_capture(conn)
		if err != nil {
			panic(err)
		}
	}
}

func session_capture(client net.Conn) error {
	server, err := net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return err
	}
	fmt.Printf("Dialed server\n")

	sides := make(chan error, 2)
	var out sync.Mutex
	go func() {
		sides <- pipeAll(client, server, &out, prefixwriter{os.Stdout, []byte("> ")})
		fmt.Printf("client-server connection done\n")
	}()
	go func() {
		sides <- pipeAll(server, client, &out, prefixwriter{os.Stdout, []byte("< ")})
		fmt.Printf("server-client connection done\n")
	}()

	i := 0
	for e := range sides {
		if e != nil && err == nil {
			err = e
		}
		i++
		fmt.Printf("Found %d errors\n", i)
		if i == 2 {
			close(sides)
		}
	}
	return err
}

func pipeAll(in, out net.Conn, ldump *sync.Mutex, dump io.Writer) error {
	var err error = nil
	for err == nil {
		err = pipeNext(in, out, ldump, dump)
	}
	if err == io.EOF {
		return nil
	}
	return err
}

func pipeNext(in, out net.Conn, ldump *sync.Mutex, dump io.Writer) error {
	lb := make([]byte, 5)
	n, err := in.Read(lb)
	if err != nil {
		return err
	} else if n != 5 {
		return fmt.Errorf("Unable to read 5 bytes.")
	}

	length := (int(lb[3]) << 8) | int(lb[4])
	rv := make([]byte, length+5)
	copy(rv, lb)
	s := 0
	n = 0
	for s < length {
		n, err = in.Read(rv[5+s:])
		if err != nil {
			return err
		}
		s += n
	}

	ldump.Lock()
	hex.Fdump(dump, lb)
	hex.Fdump(prefixwriter{dump, []byte("   ")}, rv[5:])
	ldump.Unlock()

	_, err = out.Write(rv)
	return err
}

type prefixwriter struct {
	w      io.Writer
	prefix []byte
}

func (i prefixwriter) Write(input []byte) (int, error) {
	buf := make([]byte, len(input)+len(i.prefix))
	copy(buf, i.prefix)
	copy(buf[len(i.prefix):], input)

	return i.w.Write(buf)
}

func Indent(w io.Writer, width int) io.Writer {
	prefix := make([]byte, width)
	for i, _ := range prefix {
		prefix[i] = ' '
	}
	return prefixwriter{w, prefix}
}
