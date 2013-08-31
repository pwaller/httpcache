package main

import (
	"log"
	"net"
	"os"
	"syscall"
)

func GetAddrFromFile(f *os.File) net.Addr {

	const SO_ORIGINAL_DST = 80

	addr, err := syscall.GetsockoptIPv6Mreq(int(f.Fd()), syscall.IPPROTO_IP,
		SO_ORIGINAL_DST)
	if err != nil {
		log.Printf("getsockopt(SO_ORIGINAL_DST) failed on %v: %v", f, err)
	}

	ipv4 := itod(uint(addr.Multiaddr[4])) + "." +
		itod(uint(addr.Multiaddr[5])) + "." +
		itod(uint(addr.Multiaddr[6])) + "." +
		itod(uint(addr.Multiaddr[7]))

	target := &net.TCPAddr{IP: net.ParseIP(ipv4), Port: int(addr.Multiaddr[2])*256 + int(addr.Multiaddr[3])}
	return target
}

// Determine target address for a `conn` which has been
// transparently redirected to our port
func GetOriginalAddr(conn net.Conn) net.Addr {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return conn.LocalAddr()
	}
	f, err := tcpConn.File()
	if err != nil {
		return conn.LocalAddr()
	}
	defer f.Close()
	return GetAddrFromFile(f)
}

// from pkg/net/parse.go
// Convert i to decimal string.
func itod(i uint) string {
	if i == 0 {
		return "0"
	}

	// Assemble decimal in reverse order.
	var b [32]byte
	bp := len(b)
	for ; i > 0; i /= 10 {
		bp--
		b[bp] = byte(i%10) + '0'
	}

	return string(b[bp:])
}
