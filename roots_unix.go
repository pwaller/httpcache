// Taken from crypto/x509/root_unix.go so that we can expand the root pool.
// Why doesn't go support this? :(

package main

import (
	"crypto/x509"
	"io/ioutil"
)

// Possible certificate files; stop after finding one.
var certFiles = []string{
	"/etc/ssl/certs/ca-certificates.crt",     // Linux etc
	"/etc/pki/tls/certs/ca-bundle.crt",       // Fedora/RHEL
	"/etc/ssl/ca-bundle.pem",                 // OpenSUSE
	"/etc/ssl/cert.pem",                      // OpenBSD
	"/usr/local/share/certs/ca-root-nss.crt", // FreeBSD
}

func SystemRoots() *x509.CertPool {
	roots := x509.NewCertPool()
	for _, file := range certFiles {
		data, err := ioutil.ReadFile(file)
		if err == nil {
			roots.AppendCertsFromPEM(data)
			break
		}
	}
	return roots
}
