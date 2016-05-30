package sslprobe

type compressionMethod uint8

const (
	compressionNone    compressionMethod = 0
	compressionDeflate compressionMethod = 1
	compressionGzip    compressionMethod = 2
	compressionLZW     compressionMethod = 3
)

func checkCompression(p *Probe) checkResult {
	rv := checkResult{Label: "TLS Compression", Severity: OK}

	var max TLSVersion = 0
	for _, v := range p.SupportedVersions {
		if v.Supported && v.Version < TLS_1_3 {
			max = v.Version
		}
	}
	if max < SSL_3_0 {
		rv.Result = "No protocol version found that includes compression"
		return rv
	}

	serverHello, _, _, err := p.halfHandshake(max, AllCiphers, AllCurves, []compressionMethod{5, 4, 3, 2, 1, 0})
	if err != nil {
		rv.Result = "error: " + err.Error()
		rv.Severity = Bad
		return rv
	}
	sess_l := int(serverHello[34])
	comp := compressionMethod(uint8(serverHello[37+sess_l]))
	if comp == compressionNone {
		rv.Result = "Compression not enabled"
	} else {
		rv.Result = "Compression enabled"
		rv.Severity = Bad
	}
	return rv
}

func init() {
	allCheckers["compression"] = checkCompression
}
