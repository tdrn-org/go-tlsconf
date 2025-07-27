//
// Copyright (C) 2025 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

package tlsclient

import (
	"crypto/tls"
	"reflect"

	"github.com/tdrn-org/go-conf"
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

func init() {
	(&Config{}).Bind()
}
