//
// Copyright (C) 2025 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package tlsconf_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-conf"
	"github.com/tdrn-org/go-tlsconf/tlsclient"
	"github.com/tdrn-org/go-tlsconf/tlsserver"
)

func TestEphemeralCertificate(t *testing.T) {
	listener, err := net.Listen("tcp", "localhost:")
	require.NoError(t, err)
	address := listener.Addr().String()
	certificate, err := tlsserver.GenerateEphemeralCertificate(address)
	require.NoError(t, err)
	serverConfig := tlsserver.Config{
		Config: tls.Config{
			Certificates: []tls.Certificate{*certificate},
		},
	}
	serverConfig.Bind()
	server := runHttpServer(t, listener)
	serverCertificates, err := tlsclient.FetchServerCertificates("tcp", address)
	require.NoError(t, err)
	clientConfig := tlsclient.Config{
		Config: tls.Config{
			RootCAs: serverCertificates,
		},
	}
	clientConfig.Bind()
	runHttpClient(t, address)
	server.Shutdown(context.Background())
}

func runHttpServer(t *testing.T, listener net.Listener) *http.Server {
	serverConfig, ok := conf.LookupConfiguration[*tlsserver.Config]()
	require.True(t, ok)
	server := &http.Server{
		TLSConfig: &serverConfig.Config,
	}
	go func() {
		err := server.ServeTLS(listener, "", "")
		if !errors.Is(err, http.ErrServerClosed) {
			require.NoError(t, err)
		}
	}()
	return server
}

func runHttpClient(t *testing.T, address string) {
	clientConfig, ok := conf.LookupConfiguration[*tlsclient.Config]()
	require.True(t, ok)
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &clientConfig.Config,
		},
	}
	rsp, err := client.Get("https://" + address)
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, rsp.StatusCode)
}
