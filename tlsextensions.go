package sslprobe

type ExtensionType uint16

const (
	EXT_server_name            ExtensionType = 0
	EXT_max_fragment_length                  = 1
	EXT_client_certificate_url               = 2
	EXT_trusted_ca_keys                      = 3
	EXT_truncated_hmac                       = 4
	EXT_status_request                       = 5
	EXT_elliptic_curves                      = 10
	EXT_ec_point_formats                     = 11
	EXT_signature_algorithms                 = 13
)

type TLSExtension struct {
	Type     ExtensionType
	Contents []byte
}

// Return the total length in bytes of this extension, including headers
func (x TLSExtension) Len() int {
	return len(x.Contents) + 4
}

// Copy this extension into buf
func (x TLSExtension) Copy(buf []byte) {
	if len(x.Contents) > 0xfff7 {
		panic("TLS Extension length out of bounds")
	}

	pint2(buf, int(x.Type))
	pint2(buf[2:], len(x.Contents))
	copy(buf[4:], x.Contents)
}

func ServerNameIndication(servername string) TLSExtension {
	rv := TLSExtension{Type: EXT_server_name}

	// TODO: IDN conversion
	bhost := []byte(servername)
	rv.Contents = make([]byte, len(bhost)+5)

	pint2(rv.Contents[0:], len(bhost)+3)
	rv.Contents[2] = 0x00
	pint2(rv.Contents[3:], len(bhost))
	copy(rv.Contents[5:], bhost)

	return rv
}

func HelloSupportedCurves(curves []CurveInfo) TLSExtension {
	rv := TLSExtension{Type: EXT_elliptic_curves}

	rv.Contents = make([]byte, 2+2*len(curves))
	pint2(rv.Contents[0:], 2*len(curves))

	for i, c := range curves {
		pint2(rv.Contents[2+2*i:], int(c.ID))
	}

	return rv
}

func HelloECPointFormats() TLSExtension {
	return TLSExtension{EXT_ec_point_formats, []byte{3, 0, 1, 2}}
}

func HelloSignatureAlgorithms() TLSExtension {
	hashes := []byte{1, // md5
		2, // sha1
		3, // sha224
		4, // sha256
		5, // sha384
		6} // sha512
	sigs := []byte{1, // rsa
		2, // dsa
		3} // ecdsa

	rv := TLSExtension{Type: EXT_signature_algorithms,
		Contents: make([]byte, 2+2*len(hashes)*len(sigs))}
	pint2(rv.Contents[0:], 2*len(hashes)*len(sigs))

	i := 2
	for _, h := range hashes {
		for _, s := range sigs {
			rv.Contents[i] = h
			rv.Contents[i+1] = s
			i += 2
		}
	}

	return rv
}

type TLSExtensionList []TLSExtension

// Total byte length of this extension list, including all headers
func (l TLSExtensionList) Len() int {
	if len(l) == 0 {
		return 0
	}
	rv := 2
	for _, x := range l {
		rv += x.Len()
	}
	return rv
}
