// Copyright 2013 The httpcache authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

// TODO(pwaller): all of the below

// make pip install work
// make npm work

// deal with /blah being a redirect to /blah/
// Use special cache value (empty file?) to prevent caching
// (configurably?) Respect caching headers

// improved error handling
// use race detector

// Caching of URLs with query strings?

// Security: prevent connections from unauthorized users on multi-user or
// non-firewalled systems

// If certificate doesn't exist, generate one

// TODO(pwaller): Fix race condition of multiple queries to the same url
// simultaneously. (It currently results in unsynchronized parallel writes to
// the same file == bad thing). (Maybe use `groupcache`?)

import (
	"crypto/x509"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	systls "crypto/tls"
	tls "github.com/pwaller/httpcache/mitmhttps/tls"
)

var cache_base = flag.String("cache-base", "cache", "cache base directory")
var mitm_key = flag.String("mitm-key", "mitm-ca.key", "key for proxy MITM CA")
var mitm_crt = flag.String("mitm-crt", "mitm-ca.crt", "certificate for MITM CA")
var extra_crts = flag.String("extra-crts", "httpcache-trusted.crt",
	"certificates to trust for outbound connections in addition to the system roots")

var proxy_ca_ready sync.WaitGroup
var proxy_ca tls.Certificate
var trust_db *x509.CertPool

// Stream `response` into the file at `cache_path`
func CacheResponse(cache_path string, response io.Reader) int64 {

	moved := false

	// TODO(pwaller): If any of the path fragments in cache_path are directories
	// we need to do some shuffling.

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

// Determine cache location for `req`
func getCachePath(req *http.Request) string {
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

	if stat, err := os.Stat(cache_path); err == nil && stat.IsDir() {
		cache_path += "/proxycache.base"
	}
	return cache_path
}

// Man-in-the middle `conn`.
func MITMSSL(conn net.Conn, handler http.Handler, hostname string) {

	t := time.Now()

	cert := MakeCert([]string{hostname})

	log.Printf("Took %v to generate cert", time.Since(t))

	conn.Write([]byte("HTTP/1.1 200 200 OK\r\n\r\n"))

	proxy_ca_ready.Wait()
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

func (p *CachingProxy) serveCONNECT(conn net.Conn, req *http.Request) {
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

	// Note: Might be a keep-alive connection with many requests.
	atomic.AddUint64(&p.n_served, proxy.n_served)
	atomic.AddUint64(&p.n_live, proxy.n_live)
	atomic.AddUint64(&p.nbytes_served, proxy.nbytes_served)
	atomic.AddUint64(&p.nbytes_live, proxy.nbytes_live)
}

// Determine if `conn` has been transparently redirected to us. If so, fix `req`
// to reflect the intended destination
func fixTransparentReq(conn net.Conn, req *http.Request) {
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

		// TODO(pwaller): Port numbers?

		if is_tls {
			req.URL.Scheme = "https"
			req.URL.Host += ":443"
		} else {
			req.URL.Scheme = "http"
		}
	}
}

// Swallow write errors
type writeErrorSwallower struct{ io.Writer }

func (w writeErrorSwallower) Write(p []byte) (n int, err error) {
	n, _ = w.Writer.Write(p)
	return
}

// Code to stream the result in lock-step to the client and to a cache file.
// If conn terminates, continue streaming the response into the cache.
func streamAndCache(res *http.Response, conn net.Conn, cache_path string) int64 {
	response_reader, cache_writer := io.Pipe()
	defer func() {
		err := cache_writer.Close()
		if err != nil {
			panic(err)
		}
	}()

	n_recvd := make(chan int64)
	go func() {
		n_recvd <- CacheResponse(cache_path, response_reader)
	}()

	// Swallow write errors to `conn` since we want it to keep writing to the
	// cache even if conn goes away
	w := io.MultiWriter(cache_writer, writeErrorSwallower{conn})
	err := res.Write(w)
	if err != nil {
		panic(err)
	}

	// Wait until CacheResponse is done copying the response to a file.
	n := <-n_recvd
	return n
}

func logRequest(r *http.Request) *http.Request {
	log.Println(r.Method, r.URL)
	return r
}

// ServeHTTP proxies the request given and writes the response to w.
func (p *CachingProxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	defer log.Println(" --> served", req.Method)

	hj, ok := w.(http.Hijacker)
	if !ok {
		panic("can't hijack ResponseWriter")
	}

	conn, _, err := hj.Hijack()
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	fixTransparentReq(conn, req)

	if p.requestMangler != nil {
		req = p.requestMangler(req)
	}

	logRequest(req)

	if req.Method == "CONNECT" {
		p.serveCONNECT(conn, req)
		return
	}

	cache_path := getCachePath(req)

	if fd, err := os.Open(cache_path); err == nil {
		// Respond from cache, if it exists
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

	// No cached value present. Fetch it from a real server.

	// TODO(pwaller): groupcache keyed on cache_path?
	// Maybe we want something smarter? Stream the amount that has been cached
	// to a file, then add it to the list of multi-writers? 
	// Sounds like a racey nightmare. Might be possible though.

	t := &http.Transport{Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &systls.Config{RootCAs: trust_db}}

	res, err := t.RoundTrip(req)
	if err != nil {
		log.Println("proxy roundtrip fail:", err)
		conn.Write([]byte("HTTP/1.1 500 500 Internal Server Error\r\n\r\n"))
		return
	}

	n := streamAndCache(res, conn, cache_path)

	// Record some statistics
	atomic.AddUint64(&p.n_served, 1)
	atomic.AddUint64(&p.n_live, 1)
	atomic.AddUint64(&p.nbytes_served, uint64(n))
	atomic.AddUint64(&p.nbytes_live, uint64(n))

	log.Println("  -> Live:", cache_path)
}

func loadCerts(extra_crts string) {
	trust_db = SystemRoots()
	content, err := ioutil.ReadFile(extra_crts)
	if err != nil {
		return
	}
	trust_db.AppendCertsFromPEM(content)
	log.Println("Loaded additional certificates to trust from", extra_crts)
}

func main() {
	flag.Parse()

	loadCerts(*extra_crts)

	proxy := &CachingProxy{}

	// On close, show amount served
	defer func() {
		log.Printf("Served %d (%d) connections %d (%d) bytes [(cache miss)]",
			proxy.n_served, proxy.n_live, proxy.nbytes_served, proxy.nbytes_live)
	}()

	// Servers mustn't try to use the proxy_ca before we've initialized it
	proxy_ca_ready.Add(1)

	var started sync.WaitGroup

	started.Add(1)
	// http proxy which works in both transparent and explicit-proxy configurations
	go func() {
		log.Printf("Serving on :3128")
		l, err := net.Listen("tcp4", ":3128")
		if err != nil {
			panic(err)
		}
		started.Done()
		err = http.Serve(l, proxy)
		if err != nil {
			panic(err)
		}
	}()

	started.Add(1)
	// Transparent https proxy server
	go func() {
		tlsConfig := &tls.Config{CertificateGetter: GenerateMITM{proxy_ca}}

		l, err := tls.Listen("tcp4", ":3192", tlsConfig)
		if err != nil {
			panic(err)
		}
		defer l.Close()

		started.Done()

		log.Printf("SSL listening on :3192")
		err = http.Serve(l, proxy)
		if err != nil {
			panic(err)
		}
	}()

	// Wait for servers to be listening before doing anything expensive
	// (in case GOMAXPROCS is 1 and there is no pre-emption)
	started.Wait()

	go func() {
		// This is slow, so happens in its own goroutine.
		// It should also probably happen after the listeners are started,
		// since it can't be pre-empted.
		// TODO(pwaller): fix race condition with incoming connections
		var err error
		proxy_ca, err = tls.LoadX509KeyPair(*mitm_crt, *mitm_key)
		if err != nil {
			panic(err)
		}
		proxy_ca_ready.Done()
	}()

	// TODO(pwaller): if flag.Args() is present, it's something we should exec.
	// (and forward signals to)
	// * Should wait for sockets to be listening successfully
	// * Thought, any way we can make a net namespace and do iptables transparently?
	// * Random free port assignment?

	// Await CTRL-C or kill signals
	notified := make(chan os.Signal)
	signal.Notify(notified, os.Interrupt, os.Kill)
	<-notified
}
