//
// Copyright (C) 2025 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package tlsclient

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func FetchServerCertificates(network string, address string) ([]*x509.Certificate, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			err := tls.CertificateVerificationError{}
			err.UnverifiedCertificates = make([]*x509.Certificate, 0, len(rawCerts))
			for _, rawCert := range rawCerts {
				decodedCerts, _ := decodeServerCertificates(rawCert)
				if decodedCerts != nil {
					err.UnverifiedCertificates = append(err.UnverifiedCertificates, decodedCerts...)
				}
			}
			err.Err = fmt.Errorf("%d peer certifcates received", len(err.UnverifiedCertificates))
			return &err
		},
	}
	conn, err := tls.Dial(network, address, tlsConfig)
	if conn != nil {
		defer conn.Close()
	}
	if err == nil {
		return nil, fmt.Errorf("failed to fetch server certificates (%s:%s)", network, address)
	}
	cve, ok := err.(*tls.CertificateVerificationError)
	if !ok {
		return nil, err
	}
	return cve.UnverifiedCertificates, nil
}

func AppendServerCertificates(pool *x509.CertPool, network string, address string) (*x509.CertPool, error) {
	serverCertificates, err := FetchServerCertificates(network, address)
	if err != nil {
		return nil, err
	}
	serverPool := pool
	if serverPool == nil {
		systemPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("failed to get system certificates (cause: %w)", err)
		}
		serverPool = systemPool
	}
	for _, serverCertificate := range serverCertificates {
		serverPool.AddCert(serverCertificate)
	}
	return serverPool, nil
}

func decodeServerCertificates(encoded []byte) ([]*x509.Certificate, error) {
	decoded := make([]*x509.Certificate, 0)
	block, rest := pem.Decode(encoded)
	for block != nil {
		certs, err := x509.ParseCertificates(block.Bytes)
		if err != nil {
			return decoded, fmt.Errorf("failed to parse PEM encoded certificate (cause: %w)", err)
		}
		decoded = append(decoded, certs...)
		block, rest = pem.Decode(rest)
	}
	if len(decoded) == 0 {
		certs, err := x509.ParseCertificates(encoded)
		if err != nil {
			return decoded, fmt.Errorf("failed to parse DER encoded certificate (cause: %w)", err)
		}
		decoded = append(decoded, certs...)
	}
	return decoded, nil
}
