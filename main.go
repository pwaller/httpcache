package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strings"
)

import (
	_ "bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	_ "net"
	"sort"
	"time"
)

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
			Organization: []string{"GoProxy untrusted MITM proxy Inc"},
		},
		NotBefore: time.Now(),
		NotAfter:  now.Add(365 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			// template.IPAddresses = append(template.IPAddresses, ip)
			panic("Unimplemented")
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

var CA_CERT = []byte(`-----BEGIN CERTIFICATE-----
MIICSjCCAbWgAwIBAgIBADALBgkqhkiG9w0BAQUwSjEjMCEGA1UEChMaZ2l0aHVi
LmNvbS9lbGF6YXJsL2dvcHJveHkxIzAhBgNVBAMTGmdpdGh1Yi5jb20vZWxhemFy
bC9nb3Byb3h5MB4XDTAwMDEwMTAwMDAwMFoXDTQ5MTIzMTIzNTk1OVowSjEjMCEG
A1UEChMaZ2l0aHViLmNvbS9lbGF6YXJsL2dvcHJveHkxIzAhBgNVBAMTGmdpdGh1
Yi5jb20vZWxhemFybC9nb3Byb3h5MIGdMAsGCSqGSIb3DQEBAQOBjQAwgYkCgYEA
vz9BbCaJjxs73Tvcq3leP32hAGerQ1RgvlZ68Z4nZmoVHfl+2Nr/m0dmW+GdOfpT
cs/KzfJjYGr/84x524fiuR8GdZ0HOtXJzyF5seoWnbBIuyr1PbEpgRhGQMqqOUuj
YExeLbfNHPIoJ8XZ1Vzyv3YxjbmjWA+S/uOe9HWtDbMCAwEAAaNGMEQwDgYDVR0P
AQH/BAQDAgCkMBMGA1UdJQQMMAoGCCsGAQUFBwMBMA8GA1UdEwEB/wQFMAMBAf8w
DAYDVR0RBAUwA4IBKjALBgkqhkiG9w0BAQUDgYEAIcL8huSmGMompNujsvePTUnM
oEUKtX4Eh/+s+DSfV/TyI0I+3GiPpLplEgFWuoBIJGios0r1dKh5N0TGjxX/RmGm
qo7E4jjJuo8Gs5U8/fgThZmshax2lwLtbRNwhvUVr65GdahLsZz8I+hySLuatVvR
qHHq/FQORIiNyNpq/Hg=
-----END CERTIFICATE-----`)

var CA_KEY = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQC/P0FsJomPGzvdO9yreV4/faEAZ6tDVGC+VnrxnidmahUd+X7Y
2v+bR2Zb4Z05+lNyz8rN8mNgav/zjHnbh+K5HwZ1nQc61cnPIXmx6hadsEi7KvU9
sSmBGEZAyqo5S6NgTF4tt80c8ignxdnVXPK/djGNuaNYD5L+4570da0NswIDAQAB
AoGBALzIv1b4D7ARTR3NOr6V9wArjiOtMjUrdLhO+9vIp9IEA8ZsA9gjDlCEwbkP
VDnoLjnWfraff5Os6+3JjHy1fYpUiCdnk2XA6iJSL1XWKQZPt3wOunxP4lalDgED
QTRReFbA/y/Z4kSfTXpVj68ytcvSRW/N7q5/qRtbN9804jpBAkEA0s6lvH2btSLA
mcEdwhs7zAslLbdld7rvfUeP82gPPk0S6yUqTNyikqshM9AwAktHY7WvYdKl+ghZ
HTxKVC4DoQJBAOg/IAW5RbXknP+Lf7AVtBgw3E+Yfa3mcdLySe8hjxxyZq825Zmu
Rt5Qj4Lw6ifSFNy4kiiSpE/ZCukYvUXGENMCQFkPxSWlS6tzSzuqQxBGwTSrYMG3
wb6b06JyIXcMd6Qym9OMmBpw/J5KfnSNeDr/4uFVWQtTG5xO+pdHaX+3EQECQQDl
qcbY4iX1gWVfr2tNjajSYz751yoxVbkpiT9joiQLVXYFvpu+JYEfRzsjmWl0h2Lq
AftG8/xYmaEYcMZ6wSrRAkBUwiom98/8wZVlB6qbwhU1EKDFANvICGSWMIhPx3v7
MJqTIj4uJhte2/uyVvZ6DC6noWYgy+kLgqG0S97tUEG8
-----END RSA PRIVATE KEY-----`)

var GoproxyCa, goproxyCaErr = tls.X509KeyPair(CA_CERT, CA_KEY)

const cache_base = "cache"

func logRequest(r *http.Request) *http.Request {
	log.Println(r.Method, r.URL)
	return r
}

func Respond(w http.ResponseWriter, r io.Reader) {

	hj, ok := w.(http.Hijacker)
	if !ok {
		panic("can't hijack ResponseWriter")
	}

	conn, _, err := hj.Hijack()
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	io.Copy(conn, r)
	//rw.Flush()

}

func CacheResponse(cache_path string, response_bytes []byte) {

	moved := false

	// Check that if the dir(cache_path) already exists that it is a file.
	// If not move it out of the way and move it to .../index.html later
	dir := filepath.Dir(cache_path)
	if s, err := os.Stat(dir); err == nil {
		if !s.IsDir() {
			err = os.Rename(dir, dir+".tmp.proxycache")
			if err != nil {
				panic(err)
			}
			moved = true
		}
	}

	err := os.MkdirAll(dir, os.ModePerm)
	if err != nil {
		panic(err)
	}

	if moved {
		err = os.Rename(dir+".tmp.proxycache", filepath.Join(dir, "index.html"))
		if err != nil {
			panic(err)
		}
	}

	fd, err := os.Create(cache_path)
	if err != nil {
		panic(err)
	}

	defer func() {
		err = fd.Close()
		if err != nil {
			panic(err)
		}
	}()

	io.Copy(fd, bytes.NewBuffer(response_bytes))
}

type FakeListener struct {
	c       net.Conn
	served  bool
	done    chan<- bool
	Done    <-chan bool
	handler http.Handler
}

var acceptedOne = fmt.Errorf("FakeListener.Accept: already accepted")

func NewFakeListener(conn net.Conn, handler http.Handler) *FakeListener {
	ch := make(chan bool)
	return &FakeListener{conn, false, ch, ch, handler}
}

func (l *FakeListener) Accept() (net.Conn, error) {
	if l.served {
		<-l.Done
		return nil, acceptedOne
	}
	l.served = true
	return l.c, nil
}

func (l *FakeListener) Close() error {
	return nil
}

func (l *FakeListener) Addr() net.Addr {
	return l.c.LocalAddr()
}

func (l *FakeListener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer close(l.done)
	l.handler.ServeHTTP(w, r)
}

func ServeHTTPConn(conn net.Conn, handler http.Handler) error {
	fakeListener := NewFakeListener(conn, handler)
	err := http.Serve(fakeListener, fakeListener)
	if err != nil && err != acceptedOne {
		return err
	}
	return nil
}

func MITMSSL(conn net.Conn, handler http.Handler, hostname string) {

	ca, err := x509.ParseCertificate(GoproxyCa.Certificate[0])
	certPem, keyPem, err := SignHost(ca, GoproxyCa.PrivateKey, []string{hostname})
	if err != nil {
		panic(err)
	}
	cert, err := tls.X509KeyPair(certPem, keyPem)

	conn.Write([]byte("HTTP/1.1 200 200 OK\r\n\r\n"))

	config := &tls.Config{Certificates: []tls.Certificate{cert, GoproxyCa}}
	sconn := tls.Server(conn, config)

	err = sconn.Handshake()
	if err != nil {
		panic(err)
	}

	err = ServeHTTPConn(sconn, handler)
	if err != nil {
		panic(err)
	}

	//sconn.Write([]byte("HTTP/1.1 200 200 OK\r\nConnection: close\r\n\r\nHello, world"))

}

// TODO: query string
type CachingProxy struct {
	requestMangler func(req *http.Request) *http.Request
}

// ServeHTTP proxies the request given and writes the response to w.
func (p *CachingProxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	defer log.Println(" --> served", req.Method)

	if p.requestMangler != nil {
		req = p.requestMangler(req)
	}

	logRequest(req)

	if req.Method == "CONNECT" {
		hj, ok := w.(http.Hijacker)
		if !ok {
			panic("can't hijack ResponseWriter")
		}

		conn, _, err := hj.Hijack()
		if err != nil {
			panic(err)
		}
		defer conn.Close()

		host, _, err := net.SplitHostPort(req.URL.Host)
		if err != nil {
			panic(err)
		}
		MITMSSL(conn, &CachingProxy{
			func(subreq *http.Request) *http.Request {
				subreq.URL.Scheme = "https"
				subreq.URL.Host = req.URL.Host
				return subreq
			},
		}, host)
		return
	}

	url := req.URL
	path := url.Path

	if path == "" {
		path = "/"
	}
	// Deal with directories
	if strings.HasSuffix(path, "/") {
		path += "index.html"
	}

	cache_path := filepath.Join(cache_base, url.Host, path)
	if url.RawQuery != "" {
		cache_path += "?" + url.RawQuery
	}

	if fd, err := os.Open(cache_path); err == nil {
		log.Println("  -> Cached:", cache_path)
		Respond(w, fd)
		return
	}

	res, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		log.Println("proxy roundtrip fail:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	response_bytes, err := httputil.DumpResponse(res, true)
	if err != nil {
		log.Println("proxy dumpresponse fail:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	CacheResponse(cache_path, response_bytes)
	Respond(w, bytes.NewBuffer(response_bytes))

	log.Println("  -> Live:", cache_path)
}

func main() {
	log.Printf("Serving on :3128")
	log.Fatal(http.ListenAndServe(":3128", &CachingProxy{}))
}
