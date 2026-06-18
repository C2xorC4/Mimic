package rdp

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

	"github.com/c2xorc4/mimic/internal/config"
	"github.com/c2xorc4/mimic/internal/services"
)

// prefixConn re-yields bytes already read off the wire before delegating to the
// underlying conn, so tls.Server can re-read the handshake.
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

func newTLSConfig(commonName string) (*tls.Config, error) {
	cert, err := newSelfSignedCert(commonName)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func newSelfSignedCert(commonName string) (tls.Certificate, error) {
	if commonName == "" {
		commonName = "WORKSTATION"
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
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

// jarmTLSProbes are tight JARM-only ClientHello signatures. Real clients (nmap
// rdp-ntlm-info, mstsc) do not match these, so they get a completed TLS
// handshake instead of the static Schannel ServerHello replay.
var jarmTLSProbes = []config.ProbeConfig{
	{
		Name: "jarm_tls12_probes_1_2",
		Signature: config.SignatureConfig{
			Pattern:   `\x16\x03\x03..\x01...\x03\x03................................\x20................................\x00\x8a`,
			Offset:    0,
			MinLength: 80,
		},
		ResponseFile: "responses/tls_server_hello.bin",
		RewriteRules: []config.RewriteRule{
			{Offset: 11, Length: 32, Type: "random"},
			{Offset: 44, Length: 32, Type: "echo"},
		},
	},
	{
		Name: "jarm_tls11_probe_6",
		Signature: config.SignatureConfig{
			Pattern:   `\x16\x03\x02`,
			Offset:    0,
			MinLength: 50,
		},
		ResponseFile: "responses/tls_server_hello.bin",
		RewriteRules: []config.RewriteRule{
			{Offset: 11, Length: 32, Type: "random"},
			{Offset: 44, Length: 32, Type: "echo"},
		},
	},
	// RDP Schannel static hello is TLS 1.3-shaped; JARM probes 7-10 use record
	// version 0x0301. Match the full cipher-suite block size those probes carry
	// (0x0038 = 56 bytes) so normal clients with shorter lists fall through.
	{
		Name: "jarm_tls13_probes_7_10",
		Signature: config.SignatureConfig{
			Pattern:   `\x16\x03\x01..\x01...\x03\x03................................\x20................................\x00\x38`,
			Offset:    0,
			MinLength: 80,
		},
		ResponseFile: "responses/tls_server_hello.bin",
		RewriteRules: []config.RewriteRule{
			{Offset: 11, Length: 32, Type: "random"},
			{Offset: 44, Length: 32, Type: "echo"},
		},
	},
}

type staticTLS struct {
	matcher   *services.ProbeMatcher
	responder *services.Responder
}

func newStaticTLS(servicesDir string) (*staticTLS, error) {
	baseDir := servicesDir
	if baseDir == "" {
		baseDir = "services/rdp"
	}
	matcher, err := services.NewProbeMatcher(jarmTLSProbes, nil)
	if err != nil {
		return nil, fmt.Errorf("creating JARM matcher: %w", err)
	}
	responder, err := services.NewResponder(baseDir)
	if err != nil {
		return nil, fmt.Errorf("creating responder: %w", err)
	}
	return &staticTLS{matcher: matcher, responder: responder}, nil
}

func (s *staticTLS) maybeReplay(hello []byte) ([]byte, bool) {
	match := s.matcher.Match(hello)
	if match == nil {
		return nil, false
	}
	resp, err := s.responder.GetResponse(match.ResponseFile, hello, match.RewriteRules)
	if err != nil || len(resp) == 0 {
		return nil, false
	}
	return resp, true
}