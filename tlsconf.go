//
// Copyright (C) 2025 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package tlsconf

import "crypto/tls"

type TLSConfigOption func(*tls.Config) error
