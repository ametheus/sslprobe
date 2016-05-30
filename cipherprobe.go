package sslprobe

import (
	"crypto/rand"
	"fmt"
	hex "github.com/thijzert/sslprobe/hexdump"
	"net"
)

type Probe struct {
	Host              string
	Port              int
	SupportedVersions []versionDetails
	Results           map[string]checkResult
}

func New(host string, port int) *Probe {
	rv := &Probe{Host: host, Port: port}

	rv.fillSupportedVersions()

	return rv
}

type versionDetails struct {
	Version          TLSVersion
	Supported        bool
	CertificateChain [][]byte
	SupportedCiphers []CipherInfo
	CipherPreference bool
	FFDHSize         int
	SupportedCurves  []CurveInfo
	CurvePreference  bool
}

func (p *Probe) cipherPreference(version TLSVersion) []CipherInfo {
	maxl := len(AllCiphers)
	rv := make([]CipherInfo, maxl)
	copy(rv, AllCiphers)
	candidates := 0

	for candidates < maxl {
		ciph, vv, _ := p.agreeCipher(version, rv[candidates:], AllCurves)
		if ciph.ID != 0x0000 && vv == version {
			found := false
			for i, c := range rv {
				if i < candidates {
					continue
				}
				if c.ID == ciph.ID {
					found = true
					for j := i; j > candidates; j-- {
						rv[j] = rv[j-1]
					}
					rv[candidates] = ciph
					break
				}
			}
			if !found {
				break
			}
			candidates++
		} else {
			break
		}
	}
	return rv[0:candidates]
}

func (p *Probe) fillSupportedVersions() {
	p.SupportedVersions = make([]versionDetails, 0, 6)

	for _, v := range AllVersions {
		if v == SSL_2_0 {
			cph, err := p.v2CipherPreference()
			var nvd versionDetails
			if err != nil {
				nvd = versionDetails{Version: v, Supported: false}
			} else {
				nvd = versionDetails{Version: v, Supported: true, SupportedCiphers: cph}
			}
			p.SupportedVersions = append(p.SupportedVersions, nvd)
			continue
		}

		ciphers := AllCiphers
		serverHello, serverCertificate, _, err := p.halfHandshake(v, ciphers, AllCurves, nil)
		if err != nil {
			nvd := versionDetails{Version: v, Supported: false}
			p.SupportedVersions = append(p.SupportedVersions, nvd)
			continue
		}
		sess_l := int(serverHello[34])
		ciph := uint16(serverHello[35+sess_l])<<8 | uint16(serverHello[36+sess_l])
		vv := TLSVersion(uint16(serverHello[0])<<8 | uint16(serverHello[1]))

		nvd := versionDetails{Version: v, Supported: ciph != 0x0000 && v == vv}

		if len(serverCertificate) >= 3 {
			nvd.CertificateChain = make([][]byte, 0)
			lcert := int(serverCertificate[0])<<16 | int(serverCertificate[1])<<8 | int(serverCertificate[2])
			serverCertificate = serverCertificate[3 : lcert+3]

			for len(serverCertificate) >= 3 {
				lcert = int(serverCertificate[0])<<16 | int(serverCertificate[1])<<8 | int(serverCertificate[2])
				buf := make([]byte, lcert)
				copy(buf, serverCertificate[3:3+lcert])
				nvd.CertificateChain = append(nvd.CertificateChain, buf)
				serverCertificate = serverCertificate[lcert+3:]
			}
		}

		p.SupportedVersions = append(p.SupportedVersions, nvd)
	}
}

func (p *Probe) FillDetails(version TLSVersion) {
	if version == SSL_2_0 {
		return
	}
	for i, _ := range p.SupportedVersions {
		nvd := &p.SupportedVersions[i]
		if nvd.Version != version {
			continue
		}
		if !nvd.Supported {
			continue
		}
		nvd.SupportedCiphers = p.cipherPreference(nvd.Version)
		p.fillFFDHSize(nvd)
		p.fillCurvePreferences(nvd)
	}
}

func (p *Probe) fillFFDHSize(vd *versionDetails) {
	for _, c := range vd.SupportedCiphers {
		if c.Kex != KX_FFDHE {
			continue
		}

		_, _, serverKeyExchange, err := p.halfHandshake(vd.Version, []CipherInfo{c}, AllCurves, nil)
		if err == nil && serverKeyExchange != nil {
			dh_len := int(serverKeyExchange[0])<<8 | int(serverKeyExchange[1])
			vd.FFDHSize = dh_len * 8
			return
		}
	}
}

func (p *Probe) fillCurvePreferences(vd *versionDetails) {
	maxl := len(AllCurves)
	rv := make([]CurveInfo, maxl)
	copy(rv, AllCurves)
	candidates := 0

	ciphers := make([]CipherInfo, 0, 16)
	for _, c := range vd.SupportedCiphers {
		if c.Kex == KX_ECDHE {
			ciphers = append(ciphers, c)
		}
	}

	for candidates < maxl {
		curv, err := p.agreeCurve(vd.Version, ciphers, rv[candidates:])
		if err == nil {
			found := false
			for i, c := range rv {
				if i < candidates {
					continue
				}
				if c.ID == curv.ID {
					found = true
					for j := i; j > candidates; j-- {
						rv[j] = rv[j-1]
					}
					rv[candidates] = curv
					break
				}
			}
			if !found {
				break
			}
			candidates++
		} else {
			break
		}
	}

	vd.SupportedCurves = rv[0:candidates]
}

func (p *Probe) agreeCipher(version TLSVersion, ciphers []CipherInfo, curves []CurveInfo) (rv CipherInfo, tls_version TLSVersion, err error) {
	serverHello, _, _, err := p.halfHandshake(version, ciphers, curves, nil)
	if err != nil {
		return
	}
	sess_l := int(serverHello[34])
	rv = IDCipher(uint32(serverHello[35+sess_l])<<8 | uint32(serverHello[36+sess_l]))
	tls_version = TLSVersion(uint16(serverHello[0])<<8 | uint16(serverHello[1]))
	return
}

func (p *Probe) agreeCurve(version TLSVersion, ciphers []CipherInfo, curves []CurveInfo) (rv CurveInfo, err error) {
	_, _, serverKeyExchange, err := p.halfHandshake(version, ciphers, curves, nil)
	if err != nil {
		return
	} else if serverKeyExchange == nil {
		err = fmt.Errorf("No ServerKeyExchange found")
		return
	}

	if serverKeyExchange[0] == 3 {
		// Named Curve - whew!
		id := uint16(serverKeyExchange[1])<<8 | uint16(serverKeyExchange[2])
		rv = IDCurve(id)
	} else {
		panic("Don't quite know how to handle this curve encoding")
	}
	return
}

func (p *Probe) halfHandshake(version TLSVersion, ciphers []CipherInfo, curves []CurveInfo, CompressionMethods []compressionMethod) (serverHello, serverCertificate, serverKeyExchange []byte, err error) {
	if version <= SSL_2_0 {
		return p.v2HalfHandshake(version, ciphers, curves)
	}

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

	if CompressionMethods == nil {
		CompressionMethods = []compressionMethod{compressionNone}
	}

	extensions := make(TLSExtensionList, 0, 2)
	if version >= TLS_1_0 {
		extensions = append(extensions, HelloECPointFormats())
		extensions = append(extensions, ServerNameIndication(p.Host))
		extensions = append(extensions, HelloSupportedCurves(curves))
		extensions = append(extensions, HelloSignatureAlgorithms())
	}

	extension_length := extensions.Len()
	clienthello_length := 46 + 2*len(ciphers) + 1 + len(CompressionMethods)
	if extension_length > 0 {
		clienthello_length += extension_length
	}

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
	clientHello[idx+0] = byte(len(CompressionMethods))
	for i, c := range CompressionMethods {
		clientHello[idx+1+i] = byte(c)
	}
	idx += 1 + len(CompressionMethods)

	// Extensions
	if extension_length > 0 {
		pint2(clientHello[idx:], extension_length-2)
		idx += 2

		for _, x := range extensions {
			x.Copy(clientHello[idx:])
			idx += x.Len()
		}
	}

	if false {
		hex.Dump(clientHello)
		return
	}

	_, err = c.Write(clientHello)
	if err != nil {
		return
	}

	hstype, serverHello, err := NextHandshake(c)
	if err != nil {
		serverHello = nil
		if alert, ok := err.(Alert); ok {
			// Ignore 'unrecognized name' warnings.
			if alert.Level == 1 && alert.Description == 112 {
				hstype, serverHello, err = NextHandshake(c)
				if err != nil {
					serverHello = nil
					return
				}
			} else {
				return
			}
		} else {
			return
		}
	}
	if hstype != 2 {
		serverHello = nil
		err = fmt.Errorf("Was expecting a ServerHello.")
		return
	}

	sess_l := int(serverHello[34])
	cipher := IDCipher(uint32(serverHello[35+sess_l])<<8 | uint32(serverHello[36+sess_l]))

	if cipher.Auth == AU_RSA || cipher.Auth == AU_DSA || cipher.Auth == AU_ECDSA {
		hstype, serverCertificate, err = NextHandshake(c)
		if err != nil {
			serverCertificate = nil
			return
		}
		if hstype != 11 {
			serverCertificate = nil
			err = fmt.Errorf("Was expecting a Certificate")
			return
		}
	}

	if cipher.Kex == KX_ECDHE || cipher.Kex == KX_FFDHE {
		hstype, serverKeyExchange, err = NextHandshake(c)
		if err != nil {
			serverKeyExchange = nil
			return
		}
		if hstype != 12 {
			serverKeyExchange = nil
			err = fmt.Errorf("Was expecting a ServerKeyExchange")
			return
		}
	}

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

var ERR_EncapsulationHeader error = fmt.Errorf("Unable to read encapsulation header")
var ERR_UnexpectedContentType error = fmt.Errorf("Unexpected ContentType")

func ReadCapsule(c net.Conn, expectedContentType byte) ([]byte, error) {
	lb := make([]byte, 5)
	n, err := c.Read(lb)
	if err != nil {
		return nil, err
	} else if n != 5 {
		return nil, ERR_EncapsulationHeader
	}

	length := (int(lb[3]) << 8) | int(lb[4])
	rv := make([]byte, length)
	s := 0
	n = 0
	for s < length {
		n, err = c.Read(rv[s:])
		if err != nil {
			return nil, err
		}
		s += n
	}

	if lb[0] == 21 {
		// This is a TLS alert, and therefore probably an error
		return nil, Alert{rv[0], rv[1]}
	} else if lb[0] != expectedContentType {
		return nil, ERR_UnexpectedContentType
	}

	return rv, nil
}

var hsbuf []byte = []byte{}

func NextHandshake(c net.Conn) (byte, []byte, error) {
	for len(hsbuf) < 4 {
		nb, err := ReadCapsule(c, 22)
		if err != nil {
			return 0, nil, err
		}
		hsbuf = append(hsbuf, nb...)
	}
	hstype := hsbuf[0]
	expected_length := int(hsbuf[1])<<16 | int(hsbuf[2])<<8 | int(hsbuf[3])
	for len(hsbuf) < expected_length+4 {
		nb, err := ReadCapsule(c, 22)
		if err != nil {
			return 0, nil, err
		}
		hsbuf = append(hsbuf, nb...)
	}

	rv := make([]byte, expected_length)
	copy(rv, hsbuf[4:4+expected_length])
	nb := make([]byte, len(hsbuf)-expected_length-4)
	copy(nb, hsbuf[4+expected_length:])
	hsbuf = nb
	return hstype, rv, nil
}
