//
// Copyright (C) 2025-2026 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package tlsserver_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tdrn-org/go-conf"
	"github.com/tdrn-org/go-tlsconf/tlsserver"
)

func TestDefaultConfig(t *testing.T) {
	tlsServerConfig, ok := conf.LookupConfiguration[*tlsserver.Config]()
	require.True(t, ok)
	require.NotNil(t, tlsServerConfig)
}
