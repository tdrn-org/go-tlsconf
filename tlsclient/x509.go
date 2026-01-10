//
// Copyright (C) 2025-2026 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package tlsclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/tdrn-org/go-conf"
	"github.com/tdrn-org/go-tlsconf"
	"github.com/tdrn-org/go-tlsconf/tlsserver"
)

// IgnoreSystemCerts sets the RootCAs attribute to an empty [x509.CertPool].
func IgnoreSystemCerts() tlsconf.TLSConfigOption {
	return func(config *tls.Config) error {
		config.RootCAs = x509.NewCertPool()
		return nil
	}
}

// AppendServerCertificates determines the certificates defined in the server [tls.Config]
// and adds them to RootCAs pool.
//
// If RootCAs is nil, the result pool is based on the system CAs.
// This function is meant for testing setups, to make the testing server certificate
// known to the clients.
func AppendServerCertificates() tlsconf.TLSConfigOption {
	return func(config *tls.Config) error {
		rootCAs := config.RootCAs
		if rootCAs == nil {
			systemCAs, err := x509.SystemCertPool()
			if err != nil {
				return fmt.Errorf("failed to get system certificates (cause: %w)", err)
			}
			rootCAs = systemCAs
		}
		tlsServerConfig, _ := conf.LookupConfiguration[*tlsserver.Config]()
		for _, serverCertificate := range tlsServerConfig.Certificates {
			rootCAs.AddCert(serverCertificate.Leaf)
		}
		config.RootCAs = rootCAs
		return nil
	}
}
