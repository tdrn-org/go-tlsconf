//
// Copyright (C) 2025-2026 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package tlsclient_test

import (
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-conf"
	"github.com/tdrn-org/go-tlsconf"
	"github.com/tdrn-org/go-tlsconf/tlsclient"
	"github.com/tdrn-org/go-tlsconf/tlsserver"
)

func TestDefaultConfig(t *testing.T) {
	tlsClientConfig, ok := conf.LookupConfiguration[*tlsclient.Config]()
	require.True(t, ok)
	require.NotNil(t, tlsClientConfig)
}

func TestWithSystemCerts(t *testing.T) {
	testTLSSuccess(t, "https://github.com")
}

func TestIgnoreSystemCerts(t *testing.T) {
	tlsclient.SetOptions(tlsclient.IgnoreSystemCerts())
	testTLSFailure(t, "https://github.com")
}

func TestWithoutAddServerCertificates(t *testing.T) {
	tlsserver.SetOptions(tlsserver.UseEphemeralCertificate("localhost", tlsconf.CertificateAlgorithmDefault, time.Hour))
	serverURL, server := startTestServer(t)

	testTLSFailure(t, serverURL)

	server.Shutdown(t.Context())
	server.Close()
}

func TestAddServerCertificates(t *testing.T) {
	tlsserver.SetOptions(tlsserver.UseEphemeralCertificate("localhost", tlsconf.CertificateAlgorithmDefault, time.Hour))
	serverURL, server := startTestServer(t)

	tlsclient.SetOptions(tlsclient.AddServerCertificates())
	testTLSSuccess(t, serverURL)

	server.Shutdown(t.Context())
	server.Close()
}

func testTLSSuccess(t *testing.T, url string) {
	client := tlsclient.ApplyConfig(&http.Client{})
	_, err := client.Get(url)
	require.NoError(t, err)
}

func testTLSFailure(t *testing.T, url string) {
	client := tlsclient.ApplyConfig(&http.Client{})
	_, err := client.Get(url)
	require.Error(t, err)
}

func startTestServer(t *testing.T) (string, *http.Server) {
	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	server := tlsserver.ApplyConfig(&http.Server{})
	go func() {
		err := server.ServeTLS(listener, "", "")
		require.ErrorIs(t, err, http.ErrServerClosed)
	}()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	serverURL := "https://localhost:" + port
	return serverURL, server
}
