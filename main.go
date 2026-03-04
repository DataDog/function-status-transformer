// Package main implements a Composition Function.
package main

import (
	"github.com/alecthomas/kong"

	"github.com/crossplane/function-sdk-go"
)

// CLI of this Function.
type CLI struct {
	Debug bool `short:"d" help:"Emit debug logs in addition to info logs."`

	Network     string `help:"Network on which to listen for gRPC connections." default:"tcp"`
	Address     string `help:"Address at which to listen for gRPC connections." default:":9443"`
	TLSCertsDir       string `help:"Directory containing server certs and the CA used to verify client certificates" env:"TLS_SERVER_CERTS_DIR"`
	TLSCACertFileName string `help:"Filename of the CA certificate in the TLS certs directory." default:"ca.crt" env:"TLS_CA_CERT_FILENAME"`
	TLSCertFileName   string `help:"Filename of the server certificate in the TLS certs directory." default:"tls.crt" env:"TLS_CERT_FILENAME"`
	TLSKeyFileName    string `help:"Filename of the server private key in the TLS certs directory." default:"tls.key" env:"TLS_KEY_FILENAME"`
	Insecure          bool   `help:"Run without mTLS credentials. If you supply this flag --tls-server-certs-dir will be ignored."`
}

// Run this Function.
func (c *CLI) Run() error {
	log, err := function.NewLogger(c.Debug)
	if err != nil {
		return err
	}

	return function.Serve(&Function{log: log},
		function.Listen(c.Network, c.Address),
		mtlsCertificates(c.TLSCertsDir, c.TLSCACertFileName, c.TLSCertFileName, c.TLSKeyFileName),
		function.Insecure(c.Insecure))
}

func main() {
	ctx := kong.Parse(&CLI{}, kong.Description("A Crossplane Composition Function."))
	ctx.FatalIfErrorf(ctx.Run())
}
