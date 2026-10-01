package ingest

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"time"
)

// PROTO-002, build item 107: mTLS server and client configuration.
//
// TLS 1.3 minimum on both sides. A downgrade to 1.2 or below is refused by
// the stack rather than negotiated, so "we require TLS 1.3" is enforced by
// MinVersion and not by a check somebody has to remember to write.

// ServerTLSConfig builds the control-plane side of mTLS.
//
// RequireAndVerifyClientCert: a connection without a certificate signed by our
// CA never reaches a handler. Authentication is a property of the TLS
// handshake, so there is no unauthenticated code path to forget to guard.
func ServerTLSConfig(serverCert tls.Certificate, clientCAs *x509.CertPool) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    clientCAs,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
		// Session tickets off. A resumed session skips the full handshake,
		// and a revoked collector certificate must stop working immediately
		// rather than when its ticket happens to expire.
		SessionTicketsDisabled: true,
	}
}

// ClientTLSConfig builds the collector side.
//
// RootCAs is the PINNED control-plane CA, not the system trust store. Pinning
// is the difference between "any CA in the world can impersonate the control
// plane to our collectors" and "only ours can".
func ClientTLSConfig(clientCert tls.Certificate, pinnedCAs *x509.CertPool, serverName string) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      pinnedCAs,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS13,
	}
}

// NewServer builds an mTLS HTTP server with the timeouts that bound a slow
// client. Without them a handful of slowloris connections exhaust the server.
func NewServer(addr string, h http.Handler, cfg *tls.Config) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		TLSConfig:         cfg,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
}

// ErrNoClientCert is returned when a request arrives without mTLS.
var ErrNoClientCert = errors.New("ingest: no client certificate on the connection")
