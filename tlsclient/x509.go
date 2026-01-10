//
// Copyright (C) 2025-2026 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package tlsclient

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/tdrn-org/go-conf"
	"github.com/tdrn-org/go-tlsconf"
	"github.com/tdrn-org/go-tlsconf/tlsserver"
)

// IgnoreSystemCerts sets the RootCAs attribute to an empty [x509.CertPool] thereby
// ignoring all system certificates.
func IgnoreSystemCerts() tlsconf.TLSConfigOption {
	return func(config *tls.Config) error {
		config.RootCAs = x509.NewCertPool()
		return nil
	}
}

// AddServerConfigCertificates retrieves the certificates defined in the server [tls.Config]
// and adds them to the client [tls.Config]'s RootCA pool.
//
// If the current config's RootCA pool is nil, the result pool is based on the system CAs.
// This function is primarily meant for testing setups, to make the testing server certificate
// known to the clients.
func AddServerConfigCertificates() tlsconf.TLSConfigOption {
	return func(config *tls.Config) error {
		rootCAs, err := configRootCAs(config)
		if err != nil {
			return err
		}
		tlsServerConfig, _ := conf.LookupConfiguration[*tlsserver.Config]()
		for _, serverCertificate := range tlsServerConfig.Certificates {
			rootCAs.AddCert(serverCertificate.Leaf)
		}
		config.RootCAs = rootCAs
		return nil
	}
}

// AddCertificatesFromFile adds the certificates from the given file to the client
// [tls.Config]'s RootCA pool.
//
// If the current config's RootCA pool is nil, the result pool is based on the system CAs.
func AddCertificatesFromFile(certFile string) tlsconf.TLSConfigOption {
	return func(config *tls.Config) error {
		rootCAs, err := configRootCAs(config)
		if err != nil {
			return err
		}
		certData, err := os.ReadFile(certFile)
		if err != nil {
			return fmt.Errorf("failed to read certificate file '%s' (cause: %w)", certFile, err)
		}
		decodeCertificates(rootCAs, certData)
		config.RootCAs = rootCAs
		return nil
	}
}

func decodeCertificates(pool *x509.CertPool, certData []byte) error {
	rest := certData
	for {
		if len(rest) == 0 {
			return nil
		}
		var pemBlock *pem.Block
		pemBlock, rest = pem.Decode(rest)
		if pemBlock == nil {
			return fmt.Errorf("failed to decode PEM block")
		}
		if pemBlock.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(pemBlock.Bytes)
			if err != nil {
				return fmt.Errorf("failed to parse X.509 certificate (cause: %w)", err)
			}
			pool.AddCert(cert)
		}
	}
}

func configRootCAs(config *tls.Config) (*x509.CertPool, error) {
	if config.RootCAs != nil {
		return config.RootCAs, nil
	}
	systemCAs, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to get system certificates (cause: %w)", err)
	}
	return systemCAs, nil
}
