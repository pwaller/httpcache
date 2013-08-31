package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sort"
	"strings"
	"time"

	//systls "crypto/tls"
	tls "github.com/pwaller/httpcache/mitmhttps/tls"
)

// TODO(pwaller): rw-locking for goroutine safety? Persistence?
var certCache = map[string]tls.Certificate{}

// Generate a signed tls.Certificate which is valid for the given list of
// hostnames using proxy_ca
func MakeCert(hostnames []string) *tls.Certificate {

	key := strings.Join(hostnames, " ")

	cert, ok := certCache[key]
	if ok {
		return &cert
	}

	ca, err := x509.ParseCertificate(proxy_ca.Certificate[0])
	certPem, keyPem, err := SignHost(ca, proxy_ca.PrivateKey, hostnames)
	if err != nil {
		panic(err)
	}
	cert, err = tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		panic(err)
	}
	certCache[key] = cert
	return &cert
}

type GenerateMITM struct {
	ca tls.Certificate
}

// Determine ssl server names from a net.Addr
func GetTargetServernames(addr net.Addr) (hosts []string, err error) {
	c, err := tls.Dial("tcp4", addr.String(), &tls.Config{RootCAs: trust_db})
	if err != nil {
		if err, ok := err.(x509.HostnameError); ok {
			// This is a tls error condition our side because we asked for an
			// IP connection (we don't know the hostname of the target, only
			// the IP).

			// It's okay because we're just interested in finding out what hosts
			// we should tell the client we are. If it is invalid, the client
			// will bail out.

			hosts := err.Certificate.DNSNames
			if len(hosts) == 0 {
				hosts = []string{err.Certificate.Subject.CommonName} //err.Host}
			}
			return hosts, nil
		}
		return
	}
	err = c.Handshake()
	if err != nil {
		return
	}
	hosts = c.ConnectionState().PeerCertificates[0].DNSNames
	return
}

func (gm GenerateMITM) GetCertificate(name string, conn net.Conn) *tls.Certificate {
	var names []string
	if name == "" {
		// ClientHello didn't contain a hostname we can just impersonate directly.
		// We'll have to go
		target := GetOriginalAddr(conn)

		// TODO(pwaller): cache ip:port -> certname mapping
		var err error
		names, err = GetTargetServernames(target)
		if err != nil {
			panic(err)
		}
	} else {
		names = []string{name}
	}
	return MakeCert(names)
}

func hashSorted(lst []string) *big.Int {
	c := make([]string, len(lst))
	copy(c, lst)
	sort.Strings(c)
	h := sha1.New()
	for _, s := range c {
		h.Write([]byte(s + ","))
	}
	rv := new(big.Int)
	rv.SetBytes(h.Sum(nil))
	return rv
}

func SignHost(ca *x509.Certificate, capriv interface{}, hosts []string) (pemCert []byte, pemKey []byte, err error) {
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: hashSorted(hosts),
		Issuer:       ca.Subject,
		Subject: pkix.Name{
			Organization: []string{"Proxycache MITM proxy certificate"},
		},
		NotBefore: time.Now(),
		NotAfter:  now.Add(365 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			//template.IPAddresses = append(template.IPAddresses, ip)
			//panic("Unimplemented")
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}
	certpriv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, err
	}
	pemKeyBuf := new(bytes.Buffer)
	pem.Encode(pemKeyBuf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(certpriv)})
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, ca, &certpriv.PublicKey, capriv)
	if err != nil {
		return nil, nil, err
	}
	pemCertBuf := new(bytes.Buffer)
	pem.Encode(pemCertBuf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	return pemCertBuf.Bytes(), pemKeyBuf.Bytes(), nil
}
