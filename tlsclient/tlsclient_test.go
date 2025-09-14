//
// Copyright (C) 2025 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package tlsclient_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-conf"
	"github.com/tdrn-org/go-tlsconf/tlsclient"
)

func TestDefaultConfig(t *testing.T) {
	tlsClientConfig, ok := conf.LookupConfiguration[*tlsclient.Config]()
	require.True(t, ok)
	require.NotNil(t, tlsClientConfig)
}

func TestIgnoreSystemCerts(t *testing.T) {
	tlsclient.SetOptions(tlsclient.IgnoreSystemCerts())
	tlsClientConfig, _ := conf.LookupConfiguration[*tlsclient.Config]()
	require.NotNil(t, tlsClientConfig.RootCAs)
}

func TestAppendServerCertificates(t *testing.T) {
	tlsclient.SetOptions(tlsclient.AppendServerCertificates())
	tlsClientConfig, _ := conf.LookupConfiguration[*tlsclient.Config]()
	require.NotNil(t, tlsClientConfig.RootCAs)
}

func TestApplyConfig(t *testing.T) {
	client0 := &http.Client{}
	client1 := tlsclient.ApplyConfig(client0)
	require.Equal(t, client0, client1)
	client2 := tlsclient.ApplyConfig(client1)
	require.Equal(t, client0, client2)
}
