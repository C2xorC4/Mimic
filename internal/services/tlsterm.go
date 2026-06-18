package services

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"
)

// TLS termination for decoy services.
//
// A TLS port (443/3389/5985) that only replays a static ServerHello to JARM
// probes completes no real handshake — a live client "ACKs the ClientHello but
// gets nothing back," an obvious tell (OSE-2026-001). We keep the JARM/JA3S
// fingerprint by static-replaying ONLY the scanner probes (matched in the
// listener), and terminate every other ClientHello with a real crypto/tls server
// so the handshake completes and a backend (e.g. an IIS HTTP responder) answers.

// prefixConn re-yields bytes already read off the wire (the peeked ClientHello)
// before delegating to the underlying conn, so tls.Server can re-read the
// handshake the listener consumed while deciding how to route the connection.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(b []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

// newSelfSignedCert builds a TLS certificate plausible for a standalone Windows
// host: RSA-2048 / SHA-256, CN = computer name, self-issued, ~1y validity. A real
// IIS box without an enterprise PKI presents exactly this kind of self-signed
// cert, so nmap ssl-cert sees a coherent subject rather than nothing.
func newSelfSignedCert(commonName string) (tls.Certificate, error) {
	if commonName == "" {
		commonName = "WORKSTATION"
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	// Deterministic-ish serial; randomness only needs to avoid trivial collision.
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		Issuer:                pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-30 * 24 * time.Hour),
		NotAfter:              time.Now().Add(335 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{commonName},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// newTLSConfig returns a server tls.Config bearing the self-signed cert.
func newTLSConfig(commonName string) (*tls.Config, error) {
	cert, err := newSelfSignedCert(commonName)
	if err != nil {
		return nil, fmt.Errorf("generating TLS cert: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// iisHTTPResponse builds a believable Microsoft-IIS HTTP/1.1 response for a
// request received over a terminated TLS channel. It is intentionally minimal —
// a default IIS welcome page — so the port answers as a working web server.
func iisHTTPResponse(req []byte) []byte {
	body := "<!DOCTYPE html><html><head><title>IIS Windows Server</title></head>" +
		"<body><img src=\"iisstart.png\" alt=\"IIS\"></body></html>"
	return []byte(fmt.Sprintf(
		"HTTP/1.1 200 OK\r\n"+
			"Content-Type: text/html\r\n"+
			"Server: Microsoft-IIS/10.0\r\n"+
			"X-Powered-By: ASP.NET\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n\r\n%s", len(body), body))
}
