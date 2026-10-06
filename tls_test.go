package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/crossplane/function-sdk-go"
	"google.golang.org/grpc/credentials"
)

// Use non-default filenames to exercise emissary-style configuration.
const (
	testTLSCAFile   = "client-ca.pem"
	testTLSCertFile = "server-cert.pem"
	testTLSKeyFile  = "server-key.pem"
)

func TestMTLSCertificatesRotatesServerCertificate(t *testing.T) {
	ca := newTestTLSCA(t, "server-ca")
	initial := newTestTLSCertificate(t, ca, 1, x509.ExtKeyUsageServerAuth)
	rotated := newTestTLSCertificate(t, ca, 2, x509.ExtKeyUsageServerAuth)
	client := newTestTLSCertificate(t, ca, 3, x509.ExtKeyUsageClientAuth)

	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			dir := t.TempDir()
			writeTestTLSFiles(t, dir, ca.pem, initial)
			server := testTLSCredentials(t, dir)
			config := testTLSClientConfig(ca, client)
			config.MinVersion, config.MaxVersion = version, version

			state, clientErr, serverErr := testTLSHandshake(t, server, config)
			if clientErr != nil || serverErr != nil {
				t.Fatalf("initial handshake: client = %v, server = %v", clientErr, serverErr)
			}
			if got := state.PeerCertificates[0].SerialNumber.Int64(); got != 1 {
				t.Fatalf("initial server certificate serial = %d, want 1", got)
			}

			writeTestTLSFile(t, dir, testTLSCertFile, rotated.certPEM)
			writeTestTLSFile(t, dir, testTLSKeyFile, rotated.keyPEM)

			state, clientErr, serverErr = testTLSHandshake(t, server, config)
			if clientErr != nil || serverErr != nil {
				t.Fatalf("rotated handshake: client = %v, server = %v", clientErr, serverErr)
			}
			if got := state.PeerCertificates[0].SerialNumber.Int64(); got != 2 {
				t.Errorf("rotated server certificate serial = %d, want 2", got)
			}
		})
	}
}

func TestMTLSCertificatesRotatesClientCA(t *testing.T) {
	serverCA := newTestTLSCA(t, "server-ca")
	oldCA := newTestTLSCA(t, "old-client-ca")
	newCA := newTestTLSCA(t, "new-client-ca")
	serverCert := newTestTLSCertificate(t, serverCA, 1, x509.ExtKeyUsageServerAuth)
	oldClient := newTestTLSCertificate(t, oldCA, 2, x509.ExtKeyUsageClientAuth)
	newClient := newTestTLSCertificate(t, newCA, 3, x509.ExtKeyUsageClientAuth)
	dir := t.TempDir()
	writeTestTLSFiles(t, dir, oldCA.pem, serverCert)
	server := testTLSCredentials(t, dir)

	for _, phase := range []string{"before", "after"} {
		if phase == "after" {
			writeTestTLSFile(t, dir, testTLSCAFile, newCA.pem)
		}
		for _, tc := range []struct {
			name    string
			client  testTLSCertificate
			trusted bool
		}{
			{name: "old-client", client: oldClient, trusted: phase == "before"},
			{name: "new-client", client: newClient, trusted: phase == "after"},
		} {
			t.Run(phase+"/"+tc.name, func(t *testing.T) {
				_, clientErr, serverErr := testTLSHandshake(t, server, testTLSClientConfig(serverCA, tc.client))
				if tc.trusted && (clientErr != nil || serverErr != nil) {
					t.Fatalf("trusted client rejected: client = %v, server = %v", clientErr, serverErr)
				}
				if !tc.trusted && serverErr == nil {
					t.Fatal("untrusted client accepted")
				}
			})
		}
	}
}

func TestMTLSCertificatesRejectsInvalidMaterial(t *testing.T) {
	ca := newTestTLSCA(t, "ca")
	serverCert := newTestTLSCertificate(t, ca, 1, x509.ExtKeyUsageServerAuth)
	otherCert := newTestTLSCertificate(t, ca, 2, x509.ExtKeyUsageServerAuth)
	client := newTestTLSCertificate(t, ca, 3, x509.ExtKeyUsageClientAuth)

	for _, phase := range []string{"startup", "replacement"} {
		for _, tc := range []struct {
			name     string
			file     string
			contents []byte // nil removes the file.
			wantErr  string
		}{
			{name: "missing-certificate", file: testTLSCertFile, wantErr: "cannot load X509 keypair"},
			{name: "missing-key", file: testTLSKeyFile, wantErr: "cannot load X509 keypair"},
			{name: "missing-ca", file: testTLSCAFile, wantErr: "cannot read CA certificate"},
			{name: "malformed-certificate", file: testTLSCertFile, contents: []byte("invalid"), wantErr: "cannot load X509 keypair"},
			{name: "malformed-key", file: testTLSKeyFile, contents: []byte("invalid"), wantErr: "cannot load X509 keypair"},
			{name: "malformed-ca", file: testTLSCAFile, contents: []byte("invalid"), wantErr: "invalid CA certificate"},
			{name: "mismatched-key", file: testTLSKeyFile, contents: otherCert.keyPEM, wantErr: "cannot load X509 keypair"},
		} {
			t.Run(phase+"/"+tc.name, func(t *testing.T) {
				dir := t.TempDir()
				writeTestTLSFiles(t, dir, ca.pem, serverCert)
				var server credentials.TransportCredentials
				if phase == "replacement" {
					server = testTLSCredentials(t, dir)
					_, clientErr, serverErr := testTLSHandshake(t, server, testTLSClientConfig(ca, client))
					if clientErr != nil || serverErr != nil {
						t.Fatalf("initial handshake: client = %v, server = %v", clientErr, serverErr)
					}
				}

				if tc.contents == nil {
					if err := os.Remove(filepath.Join(dir, tc.file)); err != nil {
						t.Fatal(err)
					}
				} else {
					writeTestTLSFile(t, dir, tc.file, tc.contents)
				}

				var err error
				if phase == "startup" {
					err = mtlsCertificates(dir, testTLSCAFile, testTLSCertFile, testTLSKeyFile)(&function.ServeOptions{})
				} else {
					_, _, err = testTLSHandshake(t, server, testTLSClientConfig(ca, client))
				}
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("invalid material error = %v, want %q", err, tc.wantErr)
				}

				if phase == "replacement" {
					writeTestTLSFiles(t, dir, ca.pem, serverCert)
					_, clientErr, serverErr := testTLSHandshake(t, server, testTLSClientConfig(ca, client))
					if clientErr != nil || serverErr != nil {
						t.Fatalf("handshake after repair: client = %v, server = %v", clientErr, serverErr)
					}
				}
			})
		}
	}
}

func TestMTLSCertificatesEnforcesTLSRequirements(t *testing.T) {
	ca := newTestTLSCA(t, "trusted-ca")
	untrustedCA := newTestTLSCA(t, "untrusted-ca")
	serverCert := newTestTLSCertificate(t, ca, 1, x509.ExtKeyUsageServerAuth)
	client := newTestTLSCertificate(t, ca, 2, x509.ExtKeyUsageClientAuth)
	untrustedClient := newTestTLSCertificate(t, untrustedCA, 3, x509.ExtKeyUsageClientAuth)
	dir := t.TempDir()
	writeTestTLSFiles(t, dir, ca.pem, serverCert)
	server := testTLSCredentials(t, dir)

	for _, tc := range []struct {
		name    string
		version uint16
		client  testTLSCertificate
		wantOK  bool
	}{
		{name: "TLS12", version: tls.VersionTLS12, client: client, wantOK: true},
		{name: "TLS13", version: tls.VersionTLS13, client: client, wantOK: true},
		{name: "TLS11", version: tls.VersionTLS11, client: client},
		{name: "no-client-certificate", version: tls.VersionTLS13},
		{name: "untrusted-client", version: tls.VersionTLS13, client: untrustedClient},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := testTLSClientConfig(ca, tc.client)
			config.MinVersion, config.MaxVersion = tc.version, tc.version
			_, clientErr, serverErr := testTLSHandshake(t, server, config)
			if tc.wantOK && (clientErr != nil || serverErr != nil) {
				t.Fatalf("handshake: client = %v, server = %v", clientErr, serverErr)
			}
			if !tc.wantOK && serverErr == nil {
				t.Fatal("handshake accepted without meeting TLS requirements")
			}
		})
	}
}

func TestMTLSCertificatesEmptyDirectory(t *testing.T) {
	for _, existing := range []credentials.TransportCredentials{nil, credentials.NewTLS(&tls.Config{})} {
		options := &function.ServeOptions{Credentials: existing}
		if err := mtlsCertificates("", "missing-ca", "missing-cert", "missing-key")(options); err != nil {
			t.Fatalf("empty directory: %v", err)
		}
		if options.Credentials != existing {
			t.Fatal("empty directory changed existing credentials")
		}
	}
}

type testTLSCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

type testTLSCertificate struct {
	cert    tls.Certificate
	certPEM []byte
	keyPEM  []byte
}

func newTestTLSCA(t *testing.T, name string) testTLSCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testTLSCA{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func newTestTLSCertificate(t *testing.T, ca testTLSCA, serial int64, usage x509.ExtKeyUsage) testTLSCertificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return testTLSCertificate{cert: cert, certPEM: certPEM, keyPEM: keyPEM}
}

func writeTestTLSFile(t *testing.T, dir, name string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), contents, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeTestTLSFiles(t *testing.T, dir string, caPEM []byte, server testTLSCertificate) {
	t.Helper()
	writeTestTLSFile(t, dir, testTLSCAFile, caPEM)
	writeTestTLSFile(t, dir, testTLSCertFile, server.certPEM)
	writeTestTLSFile(t, dir, testTLSKeyFile, server.keyPEM)
}

func testTLSCredentials(t *testing.T, dir string) credentials.TransportCredentials {
	t.Helper()
	options := &function.ServeOptions{}
	if err := mtlsCertificates(dir, testTLSCAFile, testTLSCertFile, testTLSKeyFile)(options); err != nil {
		t.Fatal(err)
	}
	return options.Credentials
}

func testTLSClientConfig(ca testTLSCA, client testTLSCertificate) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pool,
		ServerName: "localhost",
		NextProtos: []string{"h2"},
	}
	if len(client.cert.Certificate) > 0 {
		// Present even untrusted certificates so rejection tests exercise server
		// verification, not the client's filtering by acceptable CA names.
		config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &client.cert, nil
		}
	}
	return config
}

func testTLSHandshake(t *testing.T, server credentials.TransportCredentials, config *tls.Config) (state tls.ConnectionState, clientErr, serverErr error) {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	deadline := time.Now().Add(5 * time.Second)
	if err := serverConn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := clientConn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		conn, _, err := server.ServerHandshake(serverConn)
		if err == nil {
			_, err = conn.Write([]byte{1})
		}
		done <- err
	}()
	defer func() {
		clientConn.Close()
		serverConn.Close()
		serverErr = <-done
		for _, err := range []error{clientErr, serverErr} {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Errorf("TLS handshake timed out: %v", err)
			}
		}
	}()

	client := tls.Client(clientConn, config)
	clientErr = client.Handshake()
	if clientErr == nil {
		// TLS 1.3 may finish the client handshake before the server verifies
		// its certificate. Read a byte to observe server acceptance or an alert.
		_, clientErr = io.ReadFull(client, make([]byte, 1))
	}
	return client.ConnectionState(), clientErr, nil
}
