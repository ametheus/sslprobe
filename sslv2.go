package sslprobe

import (
	// "crypto/rand"
	"fmt"
	hex "github.com/thijzert/sslprobe/hexdump"
	"net"
	"time"
)

func (p *Probe) v2HalfHandshake(version TLSVersion, ciphers []CipherInfo, curves []CurveInfo) (serverHello, serverCertificate, serverKeyExchange []byte, err error) {
	var c net.Conn
	c, err = net.Dial("tcp", fmt.Sprintf("%s:%d", p.Host, p.Port))
	if err != nil {
		return
	}

	// Be polite - send a fatal alert before hanging up
	defer func() {
		c.Write([]byte{21, byte(uint(version) >> 8), byte(uint(version)), 0, 2, 2, 0})
		c.Close()
	}()

	clienthello_length := 9 + 32 + 3*len(ciphers)

	// HACK: the total clienthello length is dependent on clienthello_length fitting in a 2-byte length field.
	clientHello := make([]byte, clienthello_length+2, clienthello_length+3)
	rawHello := clientHello
	l := writeSSL2Length(clientHello, clienthello_length)
	if l == 3 {
		rawHello = rawHello[0 : clienthello_length+3]
		clientHello = rawHello[1 : clienthello_length+3]
	}

	clientHello[2] = 1 // hello
	pint2(clientHello[3:], int(version))
	pint2(clientHello[5:], 3*len(ciphers))
	pint2(clientHello[7:], 0)  // session_id length
	pint2(clientHello[9:], 32) // random length

	for i, c := range ciphers {
		pint3(clientHello[11+3*i:], int(c.ID))
	}

	idx := 11 + 3*len(ciphers)
	// rand.Read(clientHello[idx : idx+32])
	copy(clientHello[idx:idx+32], []byte("THIRTY-TWO INSANELY RANDOM BYTES"))

	if false {
		hex.Dump(clientHello)
		return
	}

	_, err = c.Write(clientHello)
	if err != nil {
		return
	}

	serverHello, err = readSSL2Capsule(c)
	if err != nil {
		panic(err)
		return
	}

	if serverHello[0] != 0x04 {
		serverHello = nil
		err = fmt.Errorf("Was expecting a ServerHello.")
	}

	return
}

func (p *Probe) v2CipherPreference() ([]CipherInfo, error) {
	serverHello, _, _, err := p.v2HalfHandshake(SSL_2_0, AllCiphersIncludingSSL2, nil)
	if err != nil {
		return nil, err
	}

	// padding_length := int(serverHello[1])<<8 | int(serverHello[2])
	observed_version := TLSVersion(int(serverHello[3])<<8 | int(serverHello[4]))
	cert_length := int(serverHello[5])<<8 | int(serverHello[6])
	cipher_length := int(serverHello[7])<<8 | int(serverHello[8])
	// sessionid_length := int(serverHello[9])<<8 | int(serverHello[10])

	if observed_version != SSL_2_0 {
		return nil, fmt.Errorf("Version mismatch; was expecting SSLv2; got %4x", observed_version)
	}

	rv := make([]CipherInfo, 0, cipher_length/3)
	c := serverHello[11+cert_length : 11+cert_length+cipher_length]
	for i := 0; i < cipher_length; i += 3 {
		rv = append(rv, IDCipher(uint32(c[i])<<16|uint32(c[i+1])<<8|uint32(c[i+2])))
	}

	return rv, nil
}

// Returns the value of the length field and the number of bytes read
func readSSL2Length(s []byte) (int, int) {
	if s[0]&0x80 != 0 {
		// Two-byte length field
		return int(s[0]&0x3f)<<8 | int(s[1]), 2
	} else {
		// Three-byte length field
		return int(s[0]&0x3f)<<16 | int(s[1])<<8 | int(s[2]), 3
	}
}

// Returns the number of bytes read
func writeSSL2Length(s []byte, l int) int {
	if l < 0x3fff {
		// Two-byte length field
		s[1] = byte(l & 0xff)
		s[0] = byte((l>>8)&0xff) | 0x80
		return 2
	} else {
		// Three-byte length field
		s[2] = byte(l & 0xff)
		s[1] = byte((l >> 8) & 0xff)
		s[0] = byte((l >> 16) & 0xff)
		return 3
	}
}

func readSSL2Capsule(c net.Conn) ([]byte, error) {
	c.SetDeadline(time.Now().Add(500 * time.Millisecond))
	lb := make([]byte, 5)
	n, err := c.Read(lb)
	if err != nil {
		return nil, err
	}

	length, nl := readSSL2Length(lb[0:n])
	rv := make([]byte, length)
	copy(rv, lb[nl:n])

	s := n - nl
	n = 0
	for s < length {
		n, err = c.Read(rv[s:])
		if err != nil {
			return nil, err
		}
		s += n
	}

	return rv, nil
}
