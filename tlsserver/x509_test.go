//
// Copyright (C) 2025 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package tlsserver_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-tlsconf/tlsserver"
)

func TestCertificateAlgorithms(t *testing.T) {
	algorithms := []tlsserver.CertificateAlgorithm{
		tlsserver.CertificateAlgorithmRSA2048,
		tlsserver.CertificateAlgorithmRSA3072,
		tlsserver.CertificateAlgorithmRSA4096,
		tlsserver.CertificateAlgorithmRSA8192,
		tlsserver.CertificateAlgorithmECDSA224,
		tlsserver.CertificateAlgorithmECDSA256,
		tlsserver.CertificateAlgorithmECDSA384,
		tlsserver.CertificateAlgorithmECDSA521,
		tlsserver.CertificateAlgorithmED25519,
	}
	for _, algorithm := range algorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			certificate, err := tlsserver.GenerateEphemeralCertificate("localhost", algorithm)
			require.NoError(t, err)
			require.NotNil(t, certificate)
		})
	}
}
