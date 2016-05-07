package sslprobe

import (
	"crypto/rand"
	"fmt"
	"net"
)

func CipherPreference(host string, port int, version TLSVersion) []CipherInfo {
	maxl := len(AllCiphers)
	rv := make([]CipherInfo, maxl)
	copy(rv, AllCiphers)
	candidates := 0

	for candidates < maxl {
		ciph, vv, _ := Connect(host, port, version, rv[candidates:])
		if ciph.ID != 0x0000 && vv == version {
			for i, c := range rv {
				if i <= candidates {
					continue
				}
				if c.ID == ciph.ID {
					for j := i; j > candidates; j-- {
						rv[j] = rv[j-1]
					}
					rv[candidates] = ciph
					break
				}
			}
			candidates++
		} else {
			break
		}
	}
	return rv[0:candidates]
}

type supportedProtocol struct {
	Version   TLSVersion
	Supported bool
}

func SupportedProtocols(host string, port int) []supportedProtocol {
	rv := make([]supportedProtocol, 0, 6)
	all := []TLSVersion{SSL_2_0, SSL_3_0, TLS_1_0, TLS_1_1, TLS_1_2, TLS_1_3}

	for _, v := range all {
		cph, vv, _ := Connect(host, port, v, AllCiphers)
		rv = append(rv, supportedProtocol{v, cph.ID != 0x0000 && v == vv})
	}
	return rv
}

func Connect(host string, port int, version TLSVersion, ciphers []CipherInfo) (rv CipherInfo, tls_version TLSVersion, err error) {
	rv = TLS_NULL
	var c net.Conn
	c, err = net.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return
	}

	serverName := []byte(host)
	extension_length := 2 + 2 + 2 + 3 + len(serverName)
	clienthello_length := 46 + 2*len(ciphers) + 2 + 2 + extension_length

	clientHello := make([]byte, clienthello_length)
	clientHello[0] = 22 // handshake
	pint2(clientHello[1:], int(version))
	pint2(clientHello[3:], clienthello_length-5)
	clientHello[5] = 1 // client_hello
	pint3(clientHello[6:], clienthello_length-9)
	pint2(clientHello[9:], int(version))
	rand.Read(clientHello[11:42])
	for j := 0; j < 32; j++ {
		clientHello[11+j] = byte((j%8 + 1) * 17)
	}
	clientHello[43] = 0 // Session ID length

	// Cipher List
	pint2(clientHello[44:], 2*len(ciphers))
	for i, c := range ciphers {
		pint2(clientHello[46+2*i:], int(c.ID))
	}
	idx := 46 + 2*len(ciphers)
	clientHello[idx+0] = 1 // Compression methods length
	clientHello[idx+1] = 0 // None

	idx += 2
	// Extensions
	pint2(clientHello[idx:], extension_length)

	// Server Name
	pint2(clientHello[idx+2:], 0) // server_name
	pint2(clientHello[idx+4:], 2+3+len(serverName))
	idx += 6
	pint2(clientHello[idx:], 3+len(serverName))
	idx += 2
	clientHello[idx] = 0
	pint2(clientHello[idx+1:], len(serverName))
	copy(clientHello[idx+3:], serverName)

	// fmt.Printf("%s", clientHello)
	//return

	_, err = c.Write(clientHello)
	if err != nil {
		return
	}

	serverHello, err := ReadNext(c)
	if err != nil {
		return
	}

	if serverHello[0] != 22 || serverHello[5] != 2 {
		err = fmt.Errorf("Was expecting a ServerHello.")
		return
	}
	tls_version = TLSVersion(uint16(serverHello[9])<<8 | uint16(serverHello[10]))
	sess_l := int(serverHello[43])
	cipher := uint16(serverHello[44+sess_l])<<8 | uint16(serverHello[45+sess_l])
	rv = Lookup(cipher)

	// Be polite - send a fatal alert before hanging up
	c.Write([]byte{21, byte(uint(version) >> 8), byte(uint(version)), 0, 2, 2, 0})
	c.Close()

	return
}

// Take a uint and stick it in the byte slice
func pint2(target []byte, source int) {
	target[0] = byte(source >> 8)
	target[1] = byte(source & 255)
}
func pint3(target []byte, source int) {
	target[0] = byte(source >> 16)
	target[1] = byte(source >> 8)
	target[2] = byte(source & 255)
}

func ReadNext(c net.Conn) ([]byte, error) {
	lb := make([]byte, 5)
	_, err := c.Read(lb)
	if err != nil {
		return nil, err
	}

	length := (int(lb[3]) << 8) | int(lb[4])
	rv := make([]byte, 5+length)
	copy(rv, lb)
	_, err = c.Read(rv[5:])
	if err != nil {
		return nil, err
	}

	if rv[0] == 21 {
		// This is a TLS alert, and therefore probably an error
		return nil, Alert{rv[5], rv[6]}
	}

	return rv, nil
}
