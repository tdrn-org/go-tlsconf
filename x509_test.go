//
// Copyright (C) 2025-2026 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package tlsconf_test

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-tlsconf"
)

func TestGenerateEphemeralCertificate(t *testing.T) {
	algorithms := []tlsconf.CertificateAlgorithm{
		tlsconf.CertificateAlgorithmRSA2048,
		tlsconf.CertificateAlgorithmRSA3072,
		tlsconf.CertificateAlgorithmRSA4096,
		tlsconf.CertificateAlgorithmRSA8192,
		tlsconf.CertificateAlgorithmECDSA224,
		tlsconf.CertificateAlgorithmECDSA256,
		tlsconf.CertificateAlgorithmECDSA384,
		tlsconf.CertificateAlgorithmECDSA521,
		tlsconf.CertificateAlgorithmED25519,
	}
	for _, algorithm := range algorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			certificate, err := tlsconf.GenerateEphemeralCertificate("localhost", algorithm, time.Hour)
			require.NoError(t, err)
			require.NotNil(t, certificate)
		})
	}
}

func TestWriteCertificate(t *testing.T) {
	certificate, err := tlsconf.GenerateEphemeralCertificate("localhost", tlsconf.CertificateAlgorithmDefault, time.Hour)
	require.NoError(t, err)
	dir := t.TempDir()
	certFile, keyFile, err := tlsconf.WriteCertificate(certificate, dir, "test")
	require.NoError(t, err)
	reloadedCertificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	require.NoError(t, err)
	require.Equal(t, certificate, &reloadedCertificate)
}
