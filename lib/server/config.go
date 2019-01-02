package server

type Config struct {
	Address     string
	CACertFiles []string
	CertFile    string
	KeyFile     string
}
