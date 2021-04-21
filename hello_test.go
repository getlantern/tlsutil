package tlsutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestClientHelloEdgeCases tests that ValidateClientHello is able to tolerate bad input.
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
			0x00, 0x00, 0x00, // handshake payload length: 0 bytes
		},
		// record payload too small (handshake payload should be >= 4 bytes)
		{
			// == Record header ==
			0x16,       // record type: handshake record (22)
			0x03, 0x03, // version: TLS 1.2
			0x00, 0x03, // payload length: 3 bytes
			// == Handshake header ==
			0x01,             // handshake message type: client hello
			0x00, 0x00, 0x00, // handshake payload length: 0 bytes
		},
		// payload length disagreement: record length too small
		{
			// == Record header ==
			0x16,       // record type: handshake record (22)
			0x03, 0x03, // version: TLS 1.2
			0x00, 0x04, // payload length: 4 bytes
			// == Handshake header ==
			0x01,             // handshake message type: client hello
			0x00, 0x00, 0x02, // handshake payload length: 2 bytes
			0x03, 0x03, // client version: TLS 1.2
		},
		// zero-length handshake payload
		{
			// == Record header ==
			0x16,       // record type: handshake record (22)
			0x03, 0x03, // version: TLS 1.2
			0x00, 0x04, // payload length: 4 bytes
			// == Handshake header ==
			0x01,             // handshake message type: client hello
			0x00, 0x00, 0x00, // handshake payload length: 0 bytes
		},
		// handshake payload too small
		{
			// == Record header ==
			0x16,       // record type: handshake record (22)
			0x03, 0x03, // version: TLS 1.2
			0x00, 0x06, // payload length: 6 bytes
			// == Handshake header ==
			0x01,             // handshake message type: client hello
			0x00, 0x00, 0x02, // handshake payload length: 2 bytes
			0x03, 0x03, // client version: TLS 1.2
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
