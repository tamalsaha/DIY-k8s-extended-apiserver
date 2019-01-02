package certstore

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/afero"
	"k8s.io/client-go/util/cert"
)

type CertStore struct {
	fs           afero.Fs
	dir          string
	organization []string
	prefix       string
	ca           string
	caKey        *rsa.PrivateKey
	caCert       *x509.Certificate
}

func NewCertStore(fs afero.Fs, dir string, organization ...string) (*CertStore, error) {
	err := fs.MkdirAll(dir, 0755)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create dir `%s`", dir)
	}
	return &CertStore{fs: fs, dir: dir, ca: "ca", organization: append([]string(nil), organization...)}, nil
}

func (s *CertStore) InitCA(prefix ...string) error {
	err := s.LoadCA(prefix...)
	if err == nil {
		return nil
	}
	return s.NewCA(prefix...)
}

func (s *CertStore) SetCA(crtBytes, keyBytes []byte) error {
	crt, err := cert.ParseCertsPEM(crtBytes)
	if err != nil {
		return errors.Wrap(err, "failed to parse ca certificate")
	}

	key, err := cert.ParsePrivateKeyPEM(keyBytes)
	if err != nil {
		return errors.Wrap(err, "failed to parse ca private key")
	}

	s.caCert = crt[0]
	s.caKey = key.(*rsa.PrivateKey)
	return s.Write(s.ca, s.caCert, s.caKey)
}

func (s *CertStore) LoadCA(prefix ...string) error {
	if err := s.prep(prefix...); err != nil {
		return err
	}

	if s.PairExists(s.ca, prefix...) {
		var err error
		s.caCert, s.caKey, err = s.Read(s.ca)
		return err
	}

	// only ca key found, extract ca cert from it.
	if _, err := s.fs.Stat(s.KeyFile(s.ca)); err == nil {
		keyBytes, err := afero.ReadFile(s.fs, s.KeyFile(s.ca))
		if err != nil {
			return errors.Wrapf(err, "failed to read private key `%s`", s.KeyFile(s.ca))
		}
		key, err := cert.ParsePrivateKeyPEM(keyBytes)
		if err != nil {
			return errors.Wrapf(err, "failed to parse private key `%s`", s.KeyFile(s.ca))
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return errors.Errorf("private key `%s` is not a rsa private key", s.KeyFile(s.ca))
		}
		return s.createCAFromKey(rsaKey)
	}

	return os.ErrNotExist
}

func (s *CertStore) NewCA(prefix ...string) error {
	if err := s.prep(prefix...); err != nil {
		return err
	}

	key, err := cert.NewPrivateKey()
	if err != nil {
		return errors.Wrap(err, "failed to generate private key")
	}
	return s.createCAFromKey(key)
}

func (s *CertStore) prep(prefix ...string) error {
	switch len(prefix) {
	case 0:
		s.prefix = ""
	case 1:
		s.prefix = strings.ToLower(strings.Trim(strings.TrimSpace(prefix[0]), "-")) + "-"
	default:
		return fmt.Errorf("multiple ca prefix given: %v", prefix)
	}
	return nil
}

func (s *CertStore) createCAFromKey(key *rsa.PrivateKey) error {
	var err error

	cfg := cert.Config{
		CommonName:   s.ca,
		Organization: s.organization,
		AltNames: cert.AltNames{
			DNSNames: []string{s.ca},
			IPs:      []net.IP{net.ParseIP("127.0.0.1")},
		},
	}
	crt, err := cert.NewSelfSignedCACert(cfg, key)
	if err != nil {
		return errors.Wrap(err, "failed to generate self-signed certificate")
	}
	err = s.Write(s.ca, crt, key)
	if err != nil {
		return err
	}

	s.caCert = crt
	s.caKey = key
	return nil
}

func (s *CertStore) Location() string {
	return s.dir
}

func (s *CertStore) CAName() string {
	return s.ca
}

func (s *CertStore) CACert() *x509.Certificate {
	return s.caCert
}

func (s *CertStore) CACertBytes() []byte {
	return cert.EncodeCertPEM(s.caCert)
}

func (s *CertStore) CAKey() *rsa.PrivateKey {
	return s.caKey
}

func (s *CertStore) CAKeyBytes() []byte {
	return cert.EncodePrivateKeyPEM(s.caKey)
}

func (s *CertStore) NewServerCertPair(sans cert.AltNames) (*x509.Certificate, *rsa.PrivateKey, error) {
	cfg := cert.Config{
		CommonName:   getCN(sans),
		Organization: s.organization,
		AltNames:     sans,
		Usages:       []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	key, err := cert.NewPrivateKey()
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to generate private key")
	}
	crt, err := cert.NewSignedCert(cfg, key, s.caCert, s.caKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to generate server certificate")
	}
	return crt, key, nil
}

func (s *CertStore) NewClientCertPair(sans cert.AltNames, organization ...string) (*x509.Certificate, *rsa.PrivateKey, error) {
	cfg := cert.Config{
		CommonName:   getCN(sans),
		Organization: organization,
		AltNames:     sans,
		Usages:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	key, err := cert.NewPrivateKey()
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to generate private key")
	}
	crt, err := cert.NewSignedCert(cfg, key, s.caCert, s.caKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to generate client certificate")
	}
	return crt, key, nil
}

func (s *CertStore) IsExists(name string, prefix ...string) bool {
	if err := s.prep(prefix...); err != nil {
		panic(err)
	}

	if _, err := s.fs.Stat(s.CertFile(name)); err == nil {
		return true
	}
	if _, err := s.fs.Stat(s.KeyFile(name)); err == nil {
		return true
	}
	return false
}

func (s *CertStore) PairExists(name string, prefix ...string) bool {
	if err := s.prep(prefix...); err != nil {
		panic(err)
	}

	if _, err := s.fs.Stat(s.CertFile(name)); err == nil {
		if _, err := s.fs.Stat(s.KeyFile(name)); err == nil {
			return true
		}
	}
	return false
}

func (s *CertStore) CertFile(name string) string {
	filename := strings.ToLower(name) + ".crt"
	if s.prefix != "" {
		filename = s.prefix + filename
	}
	return filepath.Join(s.dir, filename)
}

func (s *CertStore) KeyFile(name string) string {
	filename := strings.ToLower(name) + ".key"
	if s.prefix != "" {
		filename = s.prefix + filename
	}
	return filepath.Join(s.dir, filename)
}

func (s *CertStore) Write(name string, crt *x509.Certificate, key *rsa.PrivateKey) error {
	if err := afero.WriteFile(s.fs, s.CertFile(name), cert.EncodeCertPEM(crt), 0644); err != nil {
		return errors.Wrapf(err, "failed to write `%s`", s.CertFile(name))
	}
	if err := afero.WriteFile(s.fs, s.KeyFile(name), cert.EncodePrivateKeyPEM(key), 0600); err != nil {
		return errors.Wrapf(err, "failed to write `%s`", s.KeyFile(name))
	}
	return nil
}

func (s *CertStore) Read(name string) (*x509.Certificate, *rsa.PrivateKey, error) {
	crtBytes, err := afero.ReadFile(s.fs, s.CertFile(name))
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to read certificate `%s`", s.CertFile(name))
	}
	crt, err := cert.ParseCertsPEM(crtBytes)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to parse certificate `%s`", s.CertFile(name))
	}

	keyBytes, err := afero.ReadFile(s.fs, s.KeyFile(name))
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to read private key `%s`", s.KeyFile(name))
	}
	key, err := cert.ParsePrivateKeyPEM(keyBytes)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to parse private key `%s`", s.KeyFile(name))
	}
	return crt[0], key.(*rsa.PrivateKey), nil
}

func getCN(sans cert.AltNames) string {
	if len(sans.DNSNames) > 0 {
		return sans.DNSNames[0]
	}
	if len(sans.IPs) > 0 {
		return sans.IPs[0].String()
	}
	return ""
}
