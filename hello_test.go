package tlsutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestClientHellooEdgeCases tests that ValidateClientHello is able to tolerate bad input.
func TestClientHelloEdgeCases(t *testing.T) {
	badRecords := [][]byte{
		// zero-length payload
		{
			// == Record header ==
			0x16,       // record type: handshake record (22)
			0x03, 0x03, // version: TLS 1.2
			0x00, 0x00, // payload length: 0 bytes
			// == Handshake header ==
			0x01,             // handshake message type: client hello
			0x00, 0x00, 0x00, // handshake message length: 0 bytes
		},
		// payload too small (handshake payload should be >= 4 bytes)
		{
			// == Record header ==
			0x16,       // record type: handshake record (22)
			0x03, 0x03, // version: TLS 1.2
			0x00, 0x03, // payload length: 3 bytes
			// == Handshake header ==
			0x01,             // handshake message type: client hello
			0x00, 0x00, 0x00, // handshake message length: 0 bytes
		},
		// payload length disagreement
		{
			// == Record header ==
			0x16,       // record type: handshake record (22)
			0x03, 0x03, // version: TLS 1.2
			0x00, 0x04, // payload length: 4 bytes
			// == Handshake header ==
			0x01,             // handshake message type: client hello
			0x00, 0x00, 0x05, // handshake message length: 5 bytes
		},
		// zero-length handshake payload
		{
			// == Record header ==
			0x16,       // record type: handshake record (22)
			0x03, 0x03, // version: TLS 1.2
			0x00, 0x04, // payload length: 4 bytes
			// == Handshake header ==
			0x01,             // handshake message type: client hello
			0x00, 0x00, 0x00, // handshake message length: 0 bytes
		},
	}

	for i, r := range badRecords {
		t.Logf("parsing record %d", i)
		assert.NotPanics(t, func() {
			_, err := ValidateClientHello(r)
			assert.Error(t, err)
		})
	}

}
