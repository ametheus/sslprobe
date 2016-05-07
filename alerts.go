package sslprobe

import (
	"fmt"
)

type Alert struct {
	Level       byte
	Description byte
}

func (a Alert) Error() string {
	message := fmt.Sprintf("ID %d", a.Description)
	if a.Description == 0 {
		message = "close_notify"
	} else if a.Description == 10 {
		message = "unexpected_message"
	} else if a.Description == 20 {
		message = "bad_record_mac"
	} else if a.Description == 21 {
		message = "decryption_failed"
	} else if a.Description == 22 {
		message = "record_overflow"
	} else if a.Description == 30 {
		message = "decompression_failure"
	} else if a.Description == 40 {
		message = "handshake_failure"
	} else if a.Description == 41 {
		message = "no_certificate"
	} else if a.Description == 42 {
		message = "bad_certificate"
	} else if a.Description == 43 {
		message = "unsupported_certificate"
	} else if a.Description == 44 {
		message = "certificate_revoked"
	} else if a.Description == 45 {
		message = "certificate_expired"
	} else if a.Description == 46 {
		message = "certificate_unknown"
	} else if a.Description == 47 {
		message = "illegal_parameter"
	} else if a.Description == 48 {
		message = "unknown_ca"
	} else if a.Description == 49 {
		message = "access_denied"
	} else if a.Description == 50 {
		message = "decode_error"
	} else if a.Description == 51 {
		message = "decrypt_error"
	} else if a.Description == 60 {
		message = "export_restriction"
	} else if a.Description == 70 {
		message = "protocol_version"
	} else if a.Description == 71 {
		message = "insufficient_security"
	} else if a.Description == 80 {
		message = "internal_error"
	} else if a.Description == 90 {
		message = "user_canceled"
	} else if a.Description == 100 {
		message = "no_renegotiation"
	} else if a.Description == 110 {
		message = "unsupported_extension"
	}
	return fmt.Sprintf("TLS Alert, severity %d: %s", a.Level, message)
}
