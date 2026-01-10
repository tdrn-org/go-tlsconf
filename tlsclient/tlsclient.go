//
// Copyright (C) 2025-2026 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

// Package tlsconf provides functions to setup TLS on client side.
package tlsclient

import (
	"crypto/tls"
	"log/slog"
	"net/http"
	"reflect"

	"github.com/tdrn-org/go-conf"
	"github.com/tdrn-org/go-tlsconf"
)

// Config defines the bindable configuration object holding the client [tls.Config] instance.
type Config struct {
	tls.Config
}

func (c *Config) Type() reflect.Type {
	return reflect.TypeFor[*Config]()
}

func (c *Config) Bind() {
	conf.BindConfiguration(c)
}

// SetOptions applies the given options to the client [tls.Config] instance.
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

// ApplyConfig applies the client [tls.Config] instance to the given [http.Client].
//
// If the given [http.Client]'s Transport is already configured, the [http.Client]
// is returned unmodified and a warning is logged.
func ApplyConfig(client *http.Client) *http.Client {
	tlsClientConfig, _ := conf.LookupConfiguration[*Config]()
	if client.Transport == nil {
		client.Transport = &http.Transport{
			TLSClientConfig: tlsClientConfig.Config.Clone(),
		}
	} else if transport, ok := client.Transport.(*http.Transport); ok && transport.TLSClientConfig == nil {
		transport.TLSClientConfig = tlsClientConfig.Config.Clone()
	} else {
		slog.Warn("client transport already configured; TLS client config not applied")
	}
	return client
}

func init() {
	(&Config{}).Bind()
}
