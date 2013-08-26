package main

import (
	"fmt"
	"net"
	"net/http"
)

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
