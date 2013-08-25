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
	"flag"
	"math/big"
	_ "net"
	"sort"
	"time"
)

var cache_base = flag.String("cache-base", "cache", "cache base directory")
var mitm_key = flag.String("mitm-key", "mitm-ca.key", "key for proxy MITM CA")
var mitm_crt = flag.String("mitm-crt", "mitm-ca.crt", "certificate for MITM CA")

var proxy_ca tls.Certificate

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

var certCache = map[string]tls.Certificate{}

func MITMSSL(conn net.Conn, handler http.Handler, hostname string) {

	t := time.Now()

	cert, ok := certCache[hostname]
	if !ok {

		// TODO: Cache certificates, since they are slow to generate
		ca, err := x509.ParseCertificate(proxy_ca.Certificate[0])
		certPem, keyPem, err := SignHost(ca, proxy_ca.PrivateKey, []string{hostname})
		if err != nil {
			panic(err)
		}
		cert, err = tls.X509KeyPair(certPem, keyPem)
		if err != nil {
			panic(err)
		}
		certCache[hostname] = cert
	}

	log.Printf("Took %v to generate cert", time.Since(t))

	conn.Write([]byte("HTTP/1.1 200 200 OK\r\n\r\n"))

	config := &tls.Config{Certificates: []tls.Certificate{cert, proxy_ca}}
	sconn := tls.Server(conn, config)

	err := sconn.Handshake()
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

	cache_path := filepath.Join(*cache_base, url.Host, path)
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
	flag.Parse()

	var err error
	proxy_ca, err = tls.LoadX509KeyPair(*mitm_crt, *mitm_key)
	if err != nil {
		panic(err)
	}

	log.Printf("Serving on :3128")
	log.Fatal(http.ListenAndServe(":3128", &CachingProxy{}))
}
