package sslprobe

import (
	"fmt"
	"github.com/thijzert/sslprobe/ssltvd"
)

func checkHeartbleed(p *Probe) checkResult {
	rv := checkResult{Label: "Heartbleed vulnerability", Severity: OK}

	c, err := ssltvd.Dial("tcp", fmt.Sprintf("%s:%d", p.Host, p.Port), &ssltvd.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		rv.Result = "Unknown error: " + err.Error()
		return rv
	}
	defer c.Close()

	_, err = c.Heartbeat(6, []byte("potato"))
	if err != nil {
		if err == ssltvd.ErrHeartbeatNotSupported {
			rv.Result = "OK - extension not supported"
		} else if err == ssltvd.ErrHeartbeatNotAllowed {
			rv.Result = "OK - sending heartbeat messages not allowed"
		} else if err == ssltvd.ErrHeartbeatTimeout {
			rv.Result = "Timeout"
		}
		return rv
	}

	_, err = c.Heartbeat(18, []byte("hat"))
	if err != nil {
		rv.Result = "Patched implementation"
	} else {
		rv.Severity = BigFuckingProblem
		rv.Result = "Yes"
	}

	return rv
}

func init() {
	allCheckers["heartbleed"] = checkHeartbleed
}
