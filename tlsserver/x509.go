//
// Copyright (C) 2025 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package tlsserver

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
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

// CertificateAlgorithm defines the supported key algorithms
// for certificate key generation.
type CertificateAlgorithm string

const (
	CertificateAlgorithmDefault  CertificateAlgorithm = "default"  // Default is ECDSA cipher P-256 curve
	CertificateAlgorithmRSA2048  CertificateAlgorithm = "rsa2048"  // RSA cipher 2048 bit key lenght
	CertificateAlgorithmRSA3072  CertificateAlgorithm = "rsa3072"  // RSA cipher 3072 bit key lenght
	CertificateAlgorithmRSA4096  CertificateAlgorithm = "rsa4096"  // RSA cipher 4096 bit key lenght
	CertificateAlgorithmRSA8192  CertificateAlgorithm = "rsa8192"  // RSA cipher 8192 bit key lenght
	CertificateAlgorithmECDSA224 CertificateAlgorithm = "ecdsa224" // ECDSA cipher P-224 curve
	CertificateAlgorithmECDSA256 CertificateAlgorithm = "ecdsa256" // ECDSA cipher P-256 curve
	CertificateAlgorithmECDSA384 CertificateAlgorithm = "ecdsa384" // ECDSA cipher P-384 curve
	CertificateAlgorithmECDSA521 CertificateAlgorithm = "ecdsa521" // ECDSA cipher P-521 curve
	CertificateAlgorithmED25519  CertificateAlgorithm = "ed25519"  // ED25519 cipher
)

func generateCertificateKey(algorithm CertificateAlgorithm) (crypto.PublicKey, crypto.PrivateKey, error) {
	switch algorithm {
	case CertificateAlgorithmRSA2048:
		return generateRSAKey(2048)
	case CertificateAlgorithmRSA3072:
		return generateRSAKey(3072)
	case CertificateAlgorithmRSA4096:
		return generateRSAKey(4096)
	case CertificateAlgorithmRSA8192:
		return generateRSAKey(8192)
	case CertificateAlgorithmECDSA224:
		return generateECDSKey(elliptic.P224())
	case CertificateAlgorithmECDSA256, CertificateAlgorithmDefault:
		return generateECDSKey(elliptic.P256())
	case CertificateAlgorithmECDSA384:
		return generateECDSKey(elliptic.P384())
	case CertificateAlgorithmECDSA521:
		return generateECDSKey(elliptic.P521())
	case CertificateAlgorithmED25519:
		return generateED25519Key()
	}
	return nil, nil, fmt.Errorf("unknown certificate algorithm: %s", algorithm)
}

func generateRSAKey(bits int) (crypto.PublicKey, crypto.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key (cause: %w)", err)
	}
	return &key.PublicKey, key, nil
}

func generateECDSKey(c elliptic.Curve) (crypto.PublicKey, crypto.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ECSDA key (cause: %w)", err)
	}
	return &key.PublicKey, key, nil
}

func generateED25519Key() (crypto.PublicKey, crypto.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ED25519 key (cause: %w)", err)
	}
	return publicKey, privateKey, nil
}

// GenerateEphemeralCertificate generates a dummy server certificate and key
// suitable for testing purposes using the given hostname/address and algorithm.
func GenerateEphemeralCertificate(address string, algorithm CertificateAlgorithm) (*tls.Certificate, error) {
	slog.Info("generating ephemeral certificate", slog.String("address", address), slog.String("algorithm", string(algorithm)))
	hostOnly := strings.LastIndex(address, ":") < 0
	host := address
	if !hostOnly {
		host0, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("failed to decode address %q (cause %w)", address, err)
		}
		host = host0
	}
	publicKey, privateKey, err := generateCertificateKey(algorithm)
	if err != nil {
		return nil, err
	}
	x509Block, err := createEphemeralCertificateX509(host, publicKey, privateKey)
	if err != nil {
		return nil, err
	}
	encodedPrivateKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode private key (cause: %w)", err)
	}
	privateKeyBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: encodedPrivateKey,
	}
	certificate, err := tls.X509KeyPair(pem.EncodeToMemory(x509Block), pem.EncodeToMemory(privateKeyBlock))
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate (cause: %w)", err)
	}
	return &certificate, nil
}

func createEphemeralCertificateX509(host string, publicKey crypto.PublicKey, privateKey crypto.PrivateKey) (*pem.Block, error) {
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: nextCertificateSerialNumber(),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now,
		NotAfter:     now.AddDate(0, 0, 1),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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
func UseEphemeralCertificate(address string, algorithm CertificateAlgorithm) tlsconf.TLSConfigOption {
	return func(config *tls.Config) error {
		certificate, err := GenerateEphemeralCertificate(address, algorithm)
		if err != nil {
			return err
		}
		config.Certificates = []tls.Certificate{*certificate}
		return nil
	}
}
