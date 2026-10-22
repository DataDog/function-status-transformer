// Package main implements a Composition Function.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"google.golang.org/grpc/credentials"

	"github.com/crossplane/function-sdk-go"
)

// mtlsCertificates returns a ServeOption that configures mTLS using certificates
// loaded from the given directory. Unlike the SDK's function.MTLSCertificates,
// this allows configuring the certificate filenames to support emissary-provided
// TLS certs (https://datadoghq.atlassian.net/wiki/spaces/RPC/pages/4745232414).
func mtlsCertificates(dir, caCertFile, certFile, keyFile string) function.ServeOption {
	return func(o *function.ServeOptions) error {
		if dir == "" {
			return nil
		}

		config, err := rotatingMTLSConfig(dir, caCertFile, certFile, keyFile)
		if err != nil {
			return err
		}

		o.Credentials = credentials.NewTLS(config)
		return nil
	}
}

func rotatingMTLSConfig(dir, caCertFile, certFile, keyFile string) (*tls.Config, error) {
	// Validate the files at startup rather than waiting for the first connection.
	config, err := loadMTLSConfig(dir, caCertFile, certFile, keyFile)
	if err != nil {
		return nil, err
	}

	// Reload all TLS material for each new connection to pick up rotated files
	// without restarting the function.
	config.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		return loadMTLSConfig(dir, caCertFile, certFile, keyFile)
	}
	return config, nil
}

func loadMTLSConfig(dir, caCertFile, certFile, keyFile string) (*tls.Config, error) {
	crt, err := tls.LoadX509KeyPair(
		filepath.Join(dir, certFile),
		filepath.Join(dir, keyFile),
	)
	if err != nil {
		return nil, errors.Wrap(err, "cannot load X509 keypair")
	}

	ca, err := os.ReadFile(filepath.Clean(filepath.Join(dir, caCertFile)))
	if err != nil {
		return nil, errors.Wrap(err, "cannot read CA certificate")
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("invalid CA certificate")
	}

	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{crt},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}, nil
}
