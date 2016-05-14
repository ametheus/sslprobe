package hexdump

import (
	"fmt"
	"io"
	"os"
)

func Fdump(w io.Writer, buf []byte) {
	var idx int = 0

	for idx < len(buf) {
		bd := idx + 16
		if bd > len(buf) {
			bd = len(buf)
		}
		fmt.Fprintf(w, "%04x -%-48s    %-16s\n", idx, hexbytes(buf[idx:bd]), printable(buf[idx:bd]))
		idx += 16
	}
}

func Dump(buf []byte) {
	Fdump(os.Stdout, buf)
}

func hexbytes(buf []byte) []byte {
	rv := make([]byte, len(buf)*3)
	hb := []byte(fmt.Sprintf("%02x", buf))
	for i, _ := range buf {
		rv[3*i] = ' '
		if i > 0 && i%8 == 0 {
			rv[3*i] = '-'
		}
		rv[3*i+1] = hb[2*i]
		rv[3*i+2] = hb[2*i+1]
	}
	return rv
}

func printable(buf []byte) []byte {
	rv := make([]byte, len(buf))
	for i, c := range buf {
		if c >= ' ' && c <= '~' {
			rv[i] = c
		} else {
			rv[i] = '.'
		}
	}
	return rv
}
