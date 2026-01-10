//
// Copyright (C) 2025-2026 Holger de Carne
//
// This software may be modified and distributed under the terms
// of the MIT license. See the LICENSE file for details.

// Package tlsconf provides functions to setup TLS on server side.
package tlsserver

import (
	"crypto/tls"
	"log/slog"
	"net/http"
	"reflect"
	"time"

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

// UseEphemeralCertificate generates a ephemeral certificate and adds it
// to the server [tls.Config].
func UseEphemeralCertificate(address string, algorithm tlsconf.CertificateAlgorithm, lifetime time.Duration) tlsconf.TLSConfigOption {
	return func(config *tls.Config) error {
		certificate, err := tlsconf.GenerateEphemeralCertificate(address, algorithm, lifetime)
		if err != nil {
			return err
		}
		config.Certificates = []tls.Certificate{*certificate}
		return nil
	}
}

// ApplyConfig applies the server [tls.Config] instance to the given [http.Server].
//
// If the given [http.Server]'s TLS config is already set, the [http.Server]
// is returned unmodified and a warning is logged.
func ApplyConfig(server *http.Server) *http.Server {
	tlsServerConfig, _ := conf.LookupConfiguration[*Config]()
	if server.TLSConfig == nil {
		server.TLSConfig = tlsServerConfig.Clone()
	} else {
		slog.Warn("server TLS already configured; TLS server config not applied")
	}
	return server
}

func init() {
	(&Config{}).Bind()
}
