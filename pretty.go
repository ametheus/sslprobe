package sslprobe

import (
	"fmt"
	tc "github.com/thijzert/go-termcolours"
)

func (c CipherInfo) String() string {
	return c.Name
}

func (vd versionDetails) String() string {
	if vd.Supported {
		return vd.Version.String()
	}
	return fmt.Sprintf("no %s", vd.Version)
}

func (c CipherInfo) Pretty() string {
	var colour func(string) string = nil
	suffix := ""
	if c.Kex.Broken || c.Auth.Broken || c.Cipher.Broken || c.MAC.Broken {
		colour = tc.Red
		suffix = colour("  INSECURE")
	} else if c.Cipher.KeySize < 112 || c.MAC.TagSize < 160 {
		colour = tc.Yellow
		suffix = colour("  WEAK")
	}
	pad := "                                              "

	fs := tc.Yellow("no FS")
	if c.Kex.ForwardSecure {
		fs = tc.Green("  FS ")
	}

	aead := "    "
	if c.MAC.AEAD {
		aead = "AEAD"
	}

	cstr := fmt.Sprintf("%3d", c.Cipher.KeySize)
	if colour == nil && c.Kex.ForwardSecure && c.Cipher.KeySize >= 128 && c.MAC.AEAD {
		cstr = tc.Green(cstr)
		aead = tc.Green(aead)
	}

	if colour == nil {
		colour = func(s string) string {
			return s
		}
	}

	return fmt.Sprintf("%s%s  %s %s %s%s", colour(c.Name), pad[len(c.Name)%46:], fs, cstr, aead, suffix)
}

func (vd versionDetails) Pretty() string {
	var col func(string) string = nil

	if vd.Supported {
		if vd.Version == SSL_2_0 {
			col = tc.Bred
		} else if vd.Version == SSL_3_0 {
			col = tc.Red
		} else if vd.Version == TLS_1_2 || vd.Version == TLS_1_3 {
			col = tc.Bgreen
		} else {
			col = tc.Green
		}
	} else {
		if vd.Version != SSL_2_0 && vd.Version != TLS_1_3 {
			col = tc.Bblack
		}
	}

	if col != nil {
		return col(vd.Version.String())
	}
	return ""
}
