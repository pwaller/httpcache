package main

// TODO:
// read in npm certificate authority
// transparent proxying of https - difficult since need to match domain
// make pip install work
// deal with /blah being a redirect to /blah/
// Ensure that the other half of the connection is secure
// Use special cache value (empty file?) to prevent caching
// (configurably) Listen to caching headers

// Transparent HTTPs proxy: very difficult, probably need to hack/reimplement tls.

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
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

func CacheResponse(cache_path string, response io.Reader) int64 {

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
		// Failure modes?
		panic(err)
	}

	defer func() {
		err = fd.Close()
		if err != nil {
			panic(err)
		}
	}()

	n, err := io.Copy(fd, response)

	if err != nil {
		// TODO(pwaller): Failure modes?
		// Out of disk, unable to write for any reason.
		panic(err)
	}
	return n
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

	nbytes_served, n_served,
	nbytes_live, n_live uint64
}

// ServeHTTP proxies the request given and writes the response to w.
func (p *CachingProxy) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	defer log.Println(" --> served", req.Method)

	hj, ok := res.(http.Hijacker)
	if !ok {
		panic("can't hijack ResponseWriter")
	}

	conn, _, err := hj.Hijack()
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	target := GetOriginalAddr(conn)

	if target.String() != conn.LocalAddr().String() {
		// It's a transparent proxy
		req.URL.Host = req.Host
		// TODO: Deal with SSL and non-standard ports.. somehow.
		/*
			if target.Port != 80 {
				req.URL.Host += fmt.Sprintf(":%v", target.Port)
			}
		*/
		req.URL.Scheme = "http"
	}

	if p.requestMangler != nil {
		req = p.requestMangler(req)
	}

	logRequest(req)

	if req.Method == "CONNECT" {

		host, _, err := net.SplitHostPort(req.URL.Host)
		if err != nil {
			panic(err)
		}
		// TODO: figure record bytes tracked by this temporary CachingProxy
		MITMSSL(conn, &CachingProxy{
			requestMangler: func(subreq *http.Request) *http.Request {
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
		defer fd.Close()
		log.Println("  -> Cached:", cache_path)
		n, err := io.Copy(conn, fd)
		if err != nil {
			panic(err)
		}
		atomic.AddUint64(&p.n_served, 1)
		atomic.AddUint64(&p.nbytes_served, uint64(n))
		return
	}

	remote_res, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		log.Println("proxy roundtrip fail:", err)
		conn.Write([]byte("HTTP/1.1 500 500 Internal Server Error\r\n\r\n"))
		return
	}

	response_reader, response_writer := io.Pipe()
	n_recvd := make(chan int64)
	go func() {
		n_recvd <- CacheResponse(cache_path, response_reader)
	}()
	w := io.MultiWriter(response_writer, conn)
	err = remote_res.Write(w)
	if err != nil {
		panic(err)
	}
	err = response_writer.Close()
	if err != nil {
		panic(err)
	}

	// Wait until CacheResponse is done copying the response to a file.
	n := <-n_recvd

	atomic.AddUint64(&p.n_served, 1)
	atomic.AddUint64(&p.n_live, 1)
	atomic.AddUint64(&p.nbytes_served, uint64(n))
	atomic.AddUint64(&p.nbytes_live, uint64(n))

	log.Println("  -> Live:", cache_path)
}

func main() {
	flag.Parse()

	go func() {
		// This is slow, so happens in its own goroutine.
		// TODO: fix race condition with incoming connections
		var err error
		proxy_ca, err = tls.LoadX509KeyPair(*mitm_crt, *mitm_key)
		if err != nil {
			panic(err)
		}
	}()

	proxy := &CachingProxy{}
	defer func() {
		log.Printf("Served %v (%v) connections %v (%v) bytes [(cache miss)]",
			proxy.n_served, proxy.n_live, proxy.nbytes_served, proxy.nbytes_live)
	}()

	go func() {
		log.Printf("Serving on :3128")
		err := http.ListenAndServe(":3128", proxy)
		if err != nil {
			panic(err)
		}
	}()

	notified := make(chan os.Signal)
	signal.Notify(notified, os.Interrupt, os.Kill)
	<-notified
}
