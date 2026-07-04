// Package tlsutil manages the control plane's self-signed TLS
// certificate, following the same load-or-generate pattern as the
// agent's private key and the network PSK.
//
// The generated certificate is self-signed with IsCA set, so agents
// can pin it directly as a root of trust (--server-ca). This avoids a
// full CA hierarchy while still giving agents real certificate
// verification instead of InsecureSkipVerify.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// LoadOrGenerateCert ensures certPath and keyPath exist, generating a
// self-signed certificate for hosts (DNS names or IP addresses) if
// either file is missing. Existing files are left untouched, so hosts
// only applies at generation time — delete the files to re-issue.
func LoadOrGenerateCert(certPath, keyPath string, hosts []string) error {
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)

	if certErr == nil && keyErr == nil {
		return nil
	}

	if !errors.Is(certErr, os.ErrNotExist) && certErr != nil {
		return fmt.Errorf("stat cert file %q: %w", certPath, certErr)
	}

	if !errors.Is(keyErr, os.ErrNotExist) && keyErr != nil {
		return fmt.Errorf("stat key file %q: %w", keyPath, keyErr)
	}

	if certErr == nil || keyErr == nil {
		return fmt.Errorf("cert/key pair incomplete: have exactly one of %q and %q; delete it to regenerate both", certPath, keyPath)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate TLS key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "wgmesh control plane"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal TLS key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("write key file %q: %w", keyPath, err)
	}

	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("write cert file %q: %w", certPath, err)
	}

	return nil
}
