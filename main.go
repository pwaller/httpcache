// Copyright 2013 The httpcache authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

// TODO(pwaller):

// make pip install work
// make npm work

// deal with /blah being a redirect to /blah/
// Use special cache value (empty file?) to prevent caching
// (configurably) Respect to caching headers

// improved error handling
// use race detector
// split code up into different files

// Caching of URLs with query strings?

import (
	"bytes"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"

	"net/http"
	//http "github.com/pwaller/httpcache/mitmhttps/http"
	systls "crypto/tls"
	tls "github.com/pwaller/httpcache/mitmhttps/tls"
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
		if s.IsDir() {
			// TODO(pwaller): make this work in all cases, especially pip.
			//cache_path += "/proxycache.base"
		} else {
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
		err = os.Rename(dir+".tmp.proxycache", filepath.Join(dir, "proxycache.base"))
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

// TODO(pwaller): rw-locking for goroutine safety? Persistence?

var certCache = map[string]tls.Certificate{}

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

// Man-in-the middle `conn`.
func MITMSSL(conn net.Conn, handler http.Handler, hostname string) {

	t := time.Now()

	cert := MakeCert([]string{hostname})

	log.Printf("Took %v to generate cert", time.Since(t))

	conn.Write([]byte("HTTP/1.1 200 200 OK\r\n\r\n"))

	config := &tls.Config{Certificates: []tls.Certificate{*cert, proxy_ca}}
	sconn := tls.Server(conn, config)

	err := sconn.Handshake()
	if err != nil {
		panic(err)
	}

	err = ServeHTTPConn(sconn, handler)
	if err != nil {
		panic(err)
	}
}

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

	is_tls := false
	if tlsConn, ok := conn.(*tls.Conn); ok {
		is_tls = true
		f, err := tlsConn.GetFdCopy()
		if err != nil {
			panic(err)
		}
		defer f.Close()
		target = GetAddrFromFile(f)
	}

	is_transparent := target.String() != conn.LocalAddr().String()

	if is_transparent {
		// It's a transparent proxy
		req.URL.Host = req.Host

		// TODO: Port numbers?

		if is_tls {
			req.URL.Scheme = "https"
			req.URL.Host += ":443"
		} else {
			req.URL.Scheme = "http"
		}
	}

	if p.requestMangler != nil {
		req = p.requestMangler(req)
	}

	logRequest(req)

	if req.Method == "CONNECT" {
		// Note: it is assumed that all CONNECT requests are https.
		// This code needs to change if anyone needs this to behave otherwise.

		host, _, err := net.SplitHostPort(req.URL.Host)
		if err != nil {
			panic(err)
		}

		proxy := &CachingProxy{
			requestMangler: func(subreq *http.Request) *http.Request {
				subreq.URL.Scheme = "https"
				subreq.URL.Host = req.URL.Host
				return subreq
			},
		}

		MITMSSL(conn, proxy, host)

		// Might be a multi-request connection
		atomic.AddUint64(&p.n_served, proxy.n_served)
		atomic.AddUint64(&p.n_live, proxy.n_live)
		atomic.AddUint64(&p.nbytes_served, proxy.nbytes_served)
		atomic.AddUint64(&p.nbytes_live, proxy.nbytes_live)
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

	// TODO: Check if cache_path is a directory.
	// /dir/proxycache.bare?

	if stat, err := os.Stat(cache_path); err == nil && stat.IsDir() {
		cache_path += "/proxycache.base"
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

	// TODO(pwaller): Enable loading of additional certificate files via
	// commandline arguments
	/*
		rootPool := SystemRoots()
		content, err := ioutil.ReadFile("/home/pwaller/Projects/httpcache/npm-ca.crt")
		if err != nil {
			panic(err)
		}
		rootPool.AppendCertsFromPEM(content)
		tlsConfig := &systls.Config{RootCAs: rootPool}
		t := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: tlsConfig}
	*/
	t := http.DefaultTransport
	remote_res, err := t.RoundTrip(req)
	if err != nil {
		log.Println("proxy roundtrip fail:", err)
		conn.Write([]byte("HTTP/1.1 500 500 Internal Server Error\r\n\r\n"))
		return
	}

	// Code to stream the result in lock-step to the client and to a cache file.
	// Hmm. What happens if the client disconnects/errors?
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

	// Record some statistics
	atomic.AddUint64(&p.n_served, 1)
	atomic.AddUint64(&p.n_live, 1)
	atomic.AddUint64(&p.nbytes_served, uint64(n))
	atomic.AddUint64(&p.nbytes_live, uint64(n))

	log.Println("  -> Live:", cache_path)
}

type GenerateMITM struct {
	ca tls.Certificate
}

func GetTargetServernames(addr net.Addr) (hosts []string, err error) {
	// TODO(pwaller): configurable additional root CAs
	log.Printf("GetTargetServernames(%v)", addr)
	defer log.Printf(" <- GetTargetServernames(%v)", addr)
	c, err := tls.Dial("tcp4", addr.String(), nil)
	if err != nil {
		if err, ok := err.(x509.HostnameError); ok {
			// This is a tls error condition our side because we asked for an
			// IP connection (we don't know the hostname of the target, only
			// the IP).

			hosts := err.Certificate.DNSNames
			if len(hosts) == 0 {
				hosts = []string{err.Certificate.Subject.CommonName} //err.Host}
			}
			log.Println("Hosts! ", hosts)
			return hosts, nil
		}
		return
	}
	log.Println("Handshaking..")
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

	// SSL server ready for transparent
	go func() {
		tlsConfig := &tls.Config{CertificateGetter: GenerateMITM{proxy_ca}}
		// TODO: This takes a little while to come up. Any way we can improve it?
		// (maybe use tls.Listener?)
		l, err := tls.Listen("tcp4", ":3192", tlsConfig)
		if err != nil {
			panic(err)
		}
		defer l.Close()
		log.Printf("SSL listening on :3192")
		err = http.Serve(l, proxy)
		if err != nil {
			panic(err)
		}
	}()

	// TODO(pwaller): if flag.Args() is present, it's something we should exec.
	// (and forward signals to)
	// * Should wait for sockets to be listening successfully
	// * Thought, any way we can make a net namespace and do iptables transparently?

	// Await CTRL-C or kill signals
	notified := make(chan os.Signal)
	signal.Notify(notified, os.Interrupt, os.Kill)
	<-notified
}
