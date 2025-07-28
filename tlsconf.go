//
// Copyright (C) 2025 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

// Package tlsconf provides functions to setup TLS on client and server side.
package tlsconf

import "crypto/tls"

// TLSConfigOption functions are used to setup/modify a [tls.Config].
type TLSConfigOption func(*tls.Config) error

// EnableInsecureSkipVerify sets the InsecureSkipVerify attribute to true.
func EnableInsecureSkipVerify() TLSConfigOption {
	return func(config *tls.Config) error {
		config.InsecureSkipVerify = true
		return nil
	}
}
