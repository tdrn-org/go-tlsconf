//
// Copyright (C) 2025-2026 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

// Package tlsconf provides functions to setup TLS on server side.
package tlsserver

import (
	"crypto/tls"
	"reflect"

	"github.com/tdrn-org/go-conf"
	"github.com/tdrn-org/go-tlsconf"
)

// Config defines the bindable configuration object holding the server [tls.Config] instance.
type Config struct {
	tls.Config
}

func (c *Config) Type() reflect.Type {
	return reflect.TypeFor[*Config]()
}

func (c *Config) Bind() {
	conf.BindConfiguration(c)
}

// SetOptions applies the given options to the server [tls.Config] instance.
func SetOptions(options ...tlsconf.TLSConfigOption) error {
	config := &Config{}
	for _, option := range options {
		err := option(&config.Config)
		if err != nil {
			return err
		}
	}
	config.Bind()
	return nil
}

func init() {
	(&Config{}).Bind()
}
