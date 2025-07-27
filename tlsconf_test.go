//
// Copyright (C) 2025 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package tlsconf_test

import (
	"context"
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
	err = tlsserver.SetOptions(tlsserver.UseEphemeralCertificate(address))
	require.NoError(t, err)
	server := runHttpServer(t, listener)
	err = tlsclient.SetOptions(tlsclient.IgnoreSystemCerts(), tlsclient.AppendServerCertificates("tcp", address))
	require.NoError(t, err)
	runHttpClient(t, address)
	server.Shutdown(context.Background())
}

func runHttpServer(t *testing.T, listener net.Listener) *http.Server {
	serverConfig, _ := conf.LookupConfiguration[*tlsserver.Config]()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})
	server := &http.Server{
		Handler:   mux,
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
	clientConfig, _ := conf.LookupConfiguration[*tlsclient.Config]()
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &clientConfig.Config,
		},
	}
	rsp, err := client.Get("https://" + address)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, rsp.StatusCode)
}
