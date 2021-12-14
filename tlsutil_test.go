package tlsutil

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadAndWrite(t *testing.T) {
	t.Parallel()

	msg := make([]byte, 1024)
	secret, iv, seq := createTestState(t, msg)

	testFunc := func(t *testing.T, version, suite uint16) {
		t.Helper()
		buf := new(bytes.Buffer)

		writerState, err := NewConnectionState(version, suite, secret, iv, seq)
		require.NoError(t, err)
		readerState, err := NewConnectionState(version, suite, secret, iv, seq)
		require.NoError(t, err)

		_, err = WriteRecords(buf, msg, writerState)
		require.NoError(t, err)

		roundTripped, unprocessed, err := ReadRecord(buf, readerState)
		require.NoError(t, err)
		require.Equal(t, 0, len(unprocessed))
		require.Equal(t, msg, roundTripped)
	}

	TestOverAllSuites(t, testFunc)
}

func TestReadRecords(t *testing.T) {
	t.Parallel()

	const (
		// Each message will take at least two records (the max record size is 16 KB).
		msgSize = 32 * 1024

		numMsgs = 5
	)

	msgs := make([][]byte, numMsgs)
	for i := range msgs {
		msgs[i] = make([]byte, msgSize)
	}
	secret, iv, seq := createTestState(t, msgs...)
	totalMsgs := concat(msgs...)

	testFunc := func(t *testing.T, version, suite uint16) {
		t.Helper()
		buf := new(bytes.Buffer)

		writerState, err := NewConnectionState(version, suite, secret, iv, seq)
		require.NoError(t, err)
		readerState, err := NewConnectionState(version, suite, secret, iv, seq)
		require.NoError(t, err)

		for _, msg := range msgs {
			_, err = WriteRecords(buf, msg, writerState)
			require.NoError(t, err)
		}

		results, err := ReadRecords(buf, readerState)
		require.NoError(t, err)
		totalResults := []byte{}
		for _, r := range results {
			totalResults = append(totalResults, r.Data...)
		}
		require.Equal(t, len(totalMsgs), len(totalResults))
		equal, diff := compareBytes(totalResults, totalMsgs)
		require.True(t, equal, diff)
	}

	TestOverAllSuites(t, testFunc)
}

// TestAlertError ensures that UnexpectedAlertError is returned when expected.
func TestAlertError(t *testing.T) {
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		// Ensures that the server will send a 'bad certificate' alert.
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	clientCfg := &tls.Config{
		InsecureSkipVerify: true,
	}

	l, err := tls.Listen("tcp", "", serverCfg)
	require.NoError(t, err)
	defer l.Close()

	go func() {
		for {
			c, err := l.Accept()
			if err != nil && errors.Is(err, net.ErrClosed) {
				return
			}
			if err != nil {
				t.Logf("accept error: %v", err)
			}

			go func(conn net.Conn) {
				err := conn.(*tls.Conn).Handshake()
				require.Error(t, err, "expected a handshake error")
				conn.Close()
			}(c)
		}
	}()

	tcpConn, err := net.Dial("tcp", l.Addr().String())
	require.NoError(t, err)

	capConn := newCaptureConn(tcpConn)
	conn := tls.Client(capConn, clientCfg)
	handshakeErr := conn.Handshake()
	require.Error(t, handshakeErr)

	connState := new(ConnectionState)
	connState.version = tls.VersionTLS12

	var (
		readErr error
		readBuf = new(bytes.Buffer)
	)
	for capConn.buf.Len()+readBuf.Len() > 0 && readErr == nil {
		_, _, readErr = readRecord(capConn.buf, readBuf, connState, recordTypeHandshake)
	}
	require.Error(t, readErr, "read all records without error; expected to find alert record")

	var (
		decryptErr DecryptError
		alertErr   UnexpectedAlertError
	)
	require.True(t, errors.As(readErr, &decryptErr))
	require.True(t, errors.As(readErr, &alertErr))
	require.Equal(t, AlertBadCertificate, alertErr.Alert)
}

type captureConn struct {
	net.Conn
	buf *bytes.Buffer
}

func newCaptureConn(wrapped net.Conn) captureConn {
	return captureConn{wrapped, new(bytes.Buffer)}
}

func (conn captureConn) Read(b []byte) (n int, err error) {
	n, err = conn.Conn.Read(b)
	conn.buf.Write(b[:n])
	return
}

func createTestState(t *testing.T, msgs ...[]byte) (secret [52]byte, iv [16]byte, seq [8]byte) {
	t.Helper()

	var err error
	_, err = rand.Read(secret[:])
	require.NoError(t, err)
	_, err = rand.Read(iv[:])
	require.NoError(t, err)
	_, err = rand.Read(seq[:])
	require.NoError(t, err)
	for _, msg := range msgs {
		_, err = rand.Read(msg)
		require.NoError(t, err)
	}
	return
}

func concat(b ...[]byte) []byte {
	res := []byte{}
	for _, _b := range b {
		res = append(res, _b...)
	}
	return res
}

var (
	certPem = []byte(`-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----`)
	keyPem = []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIrYSSNQFaA2Hwf1duRSxKtLYX5CB04fSeQ6tF1aY/PuoAoGCCqGSM49
AwEHoUQDQgAEPR3tU2Fta9ktY+6P9G0cWO+0kETA6SFs38GecTyudlHz6xvCdz8q
EKTcWGekdmdDPsHloRNtsiCa697B2O9IFA==
-----END EC PRIVATE KEY-----`)

	cert tls.Certificate
)

func init() {
	var err error
	cert, err = tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		panic(err)
	}
}

// Compares the input slices and attempts to output a descriptive diff when the slices differ. It's
// not perfect, but it's still helpful.
func compareBytes(actual, expected []byte) (equal bool, diff string) {
	if len(expected) > len(actual) {
		if bytes.Equal(expected[:len(actual)], actual) {
			return false, fmt.Sprintf("actual (len: %d) is a prefix of expected (len: %d)", len(actual), len(expected))
		}
		return false, fmt.Sprintf("lengths differ; actual: %d, expected: %d", len(actual), len(expected))
	}
	if len(actual) > len(expected) {
		if bytes.Equal(actual[:len(expected)], expected) {
			return false, fmt.Sprintf("expected (len: %d) is a prefix of actual (len: %d)", len(expected), len(actual))
		}
		return false, fmt.Sprintf("lengths differ; actual: %d, expected: %d", len(actual), len(expected))
	}

	equal = true
	inRange := false
	rangeString := new(strings.Builder)
	lastEqual := -1
	for i := range actual {
		if actual[i] != expected[i] {
			equal = false
			if i-lastEqual <= 1 && !inRange {
				fmt.Fprintf(rangeString, "[%d, ", i)
				inRange = true
			}
		} else {
			if i-lastEqual > 1 && inRange {
				fmt.Fprintf(rangeString, "%d], ", i-1)
				inRange = false
			}
			lastEqual = i
		}
	}
	if len(actual)-lastEqual > 1 {
		fmt.Fprintf(rangeString, "%d], ", len(actual)-1)
	}
	if equal {
		return true, ""
	}
	ranges := rangeString.String()
	return false, fmt.Sprintf("different over: %s", ranges[:len(ranges)-2])
}
