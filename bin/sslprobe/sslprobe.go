package main

import (
	"fmt"
	"github.com/ametheus/sslprobe"
)

func main() {
	var nice_ciphers = []sslprobe.CipherInfo{
		sslprobe.Lookup(0xC013),
		sslprobe.Lookup(0x0033),
		sslprobe.Lookup(0x002F)}
	cipher, err := sslprobe.Connect("localhost", 1111, sslprobe.TLS_1_2, nice_ciphers)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Server chose cipher: %s\n", cipher.Name)
}
