package sslprobe

type ExtensionType uint16

const (
	EXT_server_name ExtensionType = 0
	EXT_max_fragment_length = 1
	EXT_client_certificate_url = 2
	EXT_trusted_ca_keys = 3
	EXT_truncated_hmac = 4
	EXT_status_request = 5
)

type TLSExtension struct {
	Type ExtensionType
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
	rv.Contents = make([]byte, len(bhost) + 5)

	pint2(rv.Contents[0:], len(bhost) + 3)
	rv.Contents[2] = 0x00
	pint2(rv.Contents[3:], len(bhost))
	copy(rv.Contents[5:], bhost)

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
