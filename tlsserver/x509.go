//
// Copyright (C) 2025 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package tlsserver

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/tdrn-org/go-tlsconf"
)

// GenerateEphemeralCertificate generates a dummy server certificate and key
// suitable for testing purposes.
func GenerateEphemeralCertificate(address string) (*tls.Certificate, error) {
	slog.Info("generating ephemeral certificate", slog.String("address", address))
	hostOnly := strings.LastIndex(address, ":") < 0
	host := address
	if !hostOnly {
		host0, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("failed to decode address %q (cause %w)", address, err)
		}
		host = host0
	}
	publicKey, privateKey, keyBlock, err := generateEphemeralCertificateKey()
	if err != nil {
		return nil, err
	}
	x509Block, err := createEphemeralCertificateX509(host, publicKey, privateKey)
	if err != nil {
		return nil, err
	}
	certificate, err := tls.X509KeyPair(pem.EncodeToMemory(x509Block), pem.EncodeToMemory(keyBlock))
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate (cause: %w)", err)
	}
	return &certificate, nil
}

func generateEphemeralCertificateKey() (crypto.PublicKey, crypto.PrivateKey, *pem.Block, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate key (cause: %w)", err)
	}
	encodedKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to encode key (cause: %w)", err)
	}
	keyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: encodedKey,
	}
	return &key.PublicKey, key, keyBlock, nil
}

func createEphemeralCertificateX509(host string, publicKey crypto.PublicKey, privateKey crypto.PrivateKey) (*pem.Block, error) {
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: nextCertificateSerialNumber(),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now,
		NotAfter:     now.AddDate(0, 0, 1),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		IsCA:         true,
	}
	hostIPAddress := net.ParseIP(host)
	if hostIPAddress != nil {
		template.IPAddresses = []net.IP{hostIPAddress}
	} else {
		template.DNSNames = []string{host}
	}
	x509Bytes, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate (cause: %w)", err)
	}
	x509Block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: x509Bytes,
	}
	return x509Block, nil
}

var certificateSerialNumberLock sync.Mutex = sync.Mutex{}

func nextCertificateSerialNumber() *big.Int {
	certificateSerialNumberLock.Lock()
	defer certificateSerialNumberLock.Unlock()
	// wait at least one update, to ensure this functions never returns the same result twice
	current := time.Now().UnixMilli()
	for {
		next := time.Now().UnixMilli()
		if next != current {
			return big.NewInt(next)
		}
	}
}

// UseEphemeralCertificate generates a ephemeral certificate and adds it
// to the server [tls.Config].
func UseEphemeralCertificate(address string) tlsconf.TLSConfigOption {
	return func(config *tls.Config) error {
		certificate, err := GenerateEphemeralCertificate(address)
		if err != nil {
			return err
		}
		config.Certificates = []tls.Certificate{*certificate}
		return nil
	}
}
