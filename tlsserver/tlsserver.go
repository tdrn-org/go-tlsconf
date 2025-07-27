//
// Copyright (C) 2025 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package tlsserver

import (
	"crypto/tls"
	"reflect"

	"github.com/tdrn-org/go-conf"
	"github.com/tdrn-org/go-tlsconf"
)

type Config struct {
	tls.Config
}

func (c *Config) Type() reflect.Type {
	return reflect.TypeFor[*Config]()
}

func (c *Config) Bind() {
	conf.BindConfiguration(c)
}

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
