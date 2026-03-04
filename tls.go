// Package main implements a Composition Function.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"

	"github.com/crossplane/function-sdk-go"
	"github.com/pkg/errors"
	"google.golang.org/grpc/credentials"
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

		crt, err := tls.LoadX509KeyPair(
			filepath.Join(dir, certFile),
			filepath.Join(dir, keyFile),
		)
		if err != nil {
			return errors.Wrap(err, "cannot load X509 keypair")
		}

		ca, err := os.ReadFile(filepath.Clean(filepath.Join(dir, caCertFile)))
		if err != nil {
			return errors.Wrap(err, "cannot read CA certificate")
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return errors.New("invalid CA certificate")
		}

		o.Credentials = credentials.NewTLS(&tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{crt},
			ClientCAs:    pool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
		})

		return nil
	}
}
