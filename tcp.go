package main

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/shadowsocks/go-shadowsocks2/socks"
)

// Create a SOCKS server listening on addr and proxy to server.
func socksLocal(addr, server string, shadow func(net.Conn) net.Conn, proxy string) {
	logf("SOCKS proxy %s <-> %s", addr, server)
	tcpLocal(addr, server, shadow, func(c net.Conn) (socks.Addr, error) { return socks.Handshake(c) }, proxy)
}

// Create a TCP tunnel from addr to target via server.
func tcpTun(addr, server, target string, shadow func(net.Conn) net.Conn, proxy string) {
	tgt := socks.ParseAddr(target)
	if tgt == nil {
		logf("invalid target address %q", target)
		return
	}
	logf("TCP tunnel %s <-> %s <-> %s", addr, server, target)
	tcpLocal(addr, server, shadow, func(net.Conn) (socks.Addr, error) { return tgt, nil }, proxy)
}

// Listen on addr and proxy to server to reach target from getAddr.
func tcpLocal(addr, server string, shadow func(net.Conn) net.Conn, getAddr func(net.Conn) (socks.Addr, error), proxy string) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		logf("failed to listen on %s: %v", addr, err)
		return
	}

	for {
		c, err := l.Accept()
		if err != nil {
			logf("failed to accept: %s", err)
			continue
		}

		go func() {
			defer c.Close()
			tgt, err := getAddr(c)
			if err != nil {

				// UDP: keep the connection until disconnect then free the UDP socket
				if err == socks.InfoUDPAssociate {
					buf := make([]byte, 1)
					// block here
					for {
						_, err := c.Read(buf)
						if err, ok := err.(net.Error); ok && err.Timeout() {
							continue
						}
						logf("UDP Associate End.")
						return
					}
				}

				logf("failed to get target address: %v", err)
				return
			}

			var rc net.Conn
			if proxy != "" {
				if strings.HasPrefix(proxy, "http://") {
					rc, err = net.Dial("tcp", proxy[7:])
					request := fmt.Sprintf("CONNECT %s HTTP/1.1\r\n\r\n", server)
					_, err = rc.Write([]byte(request))
					var response [128]byte
					var n int
					n, err = rc.Read(response[:])
					fmt.Println(string(response[:n]))
					if !strings.HasPrefix(string(response[:n]), "HTTP/1.1 200 ") {
						logf("failed to connect to server %v: %v", server, string(response[:n]))
						return
					}
				} else if strings.HasPrefix(proxy, "socks://") {
					// TODO
				} else if strings.HasPrefix(proxy, "base64://") {
					request, err := base64.StdEncoding.DecodeString(proxy[9:])
					if err != nil {
						logf("invalid proxy %v: %v", proxy, err)
						return
					}
					rc, err = net.Dial("tcp", server)
					if err != nil {
						logf("failed to connect to server %v: %v", server, err)
						return
					}
					_, err = rc.Write([]byte(request))
				} else {
					logf("invalid proxy server %v: %v", server, err)
					return
				}
			} else {
				rc, err = net.Dial("tcp", server)
			}
			if err != nil {
				logf("failed to connect to server %v: %v", server, err)
				return
			}
			defer rc.Close()
			if config.TCPCork {
				rc = timedCork(rc, 10*time.Millisecond, 1280)
			}
			rc = shadow(rc)

			if _, err = rc.Write(tgt); err != nil {
				logf("failed to send target address: %v", err)
				return
			}

			logf("proxy %s <-> %s <-> %s", c.RemoteAddr(), server, tgt)
			err = relay(rc, c)
			if err != nil {
				if err, ok := err.(net.Error); ok && err.Timeout() {
					return // ignore i/o timeout
				}
				logf("relay error: %v", err)
			}
		}()
	}
}

// Listen on addr for incoming connections.
func tcpRemote(addr string, shadow func(net.Conn) net.Conn, proxy string, dns string) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		logf("failed to listen on %s: %v", addr, err)
		return
	}

	logf("listening TCP on %s", addr)
	for {
		c, err := l.Accept()
		if err != nil {
			logf("failed to accept: %v", err)
			continue
		}

		go func() {
			defer c.Close()
			if config.TCPCork {
				c = timedCork(c, 10*time.Millisecond, 1280)
			}
			sc := shadow(c)

			tgt, err := socks.ReadAddr(sc)
			if err != nil {
				logf("failed to get target address from %v: %v", c.RemoteAddr(), err)
				// drain c to avoid leaking server behavioral features
				// see https://www.ndss-symposium.org/ndss-paper/detecting-probe-resistant-proxies/
				_, err = io.Copy(ioutil.Discard, c)
				if err != nil {
					logf("discard error: %v", err)
				}
				return
			}

			if tgt.Port() == 53 && dns != "" {
				err := relayDNS(sc, dns)
				if err != nil {
					logf("dns failed: %v", err)
				}
				return
			}

			var rc net.Conn
			if proxy != "" {
				if strings.HasPrefix(proxy, "http://") {
					rc, err = net.Dial("tcp", proxy[7:])
					request := fmt.Sprintf("CONNECT %s HTTP/1.1\r\n\r\n", tgt.String())
					_, err = rc.Write([]byte(request))
					var response [128]byte
					var n int
					n, err = rc.Read(response[:])
					fmt.Println(string(response[:n]))
					if !strings.HasPrefix(string(response[:n]), "HTTP/1.1 200 ") {
						logf("failed to connect to server %v: %v", tgt.String(), string(response[:n]))
						return
					}
				} else {
					logf("invalid proxy server %v: %v", tgt.String(), err)
					return
				}
			} else {
				rc, err = net.Dial("tcp", tgt.String())
			}

			if err != nil {
				logf("failed to connect to target: %v", err)
				return
			}
			defer rc.Close()

			logf("proxy %s <-> %s", c.RemoteAddr(), tgt)
			err = relay(sc, rc)
			if err != nil {
				if err, ok := err.(net.Error); ok && err.Timeout() {
					return // ignore i/o timeout
				}
				logf("relay error: %v", err)
			}
		}()
	}
}

// relay copies between left and right bidirectionally. Returns any error occurred.
func relay(left, right net.Conn) error {
	var err, err1 error
	var wg sync.WaitGroup
	var wait = 5 * time.Second
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err1 = io.Copy(right, left)
		right.SetReadDeadline(time.Now().Add(wait)) // unblock read on right
	}()

	_, err = io.Copy(left, right)
	left.SetReadDeadline(time.Now().Add(wait)) // unblock read on left
	wg.Wait()

	if err1 != nil {
		err = err1
	}
	return err
}

func relayDNS(sc net.Conn, dns string) error {
	var wait = 5 * time.Second
	sc.SetReadDeadline(time.Now().Add(wait))

	var b [1460]byte
	n, err := sc.Read(b[:])
	if err != nil {
		return err
	}

	rc, err := net.Dial("udp", dns)
	defer rc.Close()
	rc.SetReadDeadline(time.Now().Add(wait))

	_, err = rc.Write(b[2:n])
	if err != nil {
		return err
	}

	n, err = rc.Read(b[2:])
	if err != nil {
		return err
	}

	binary.BigEndian.PutUint16(b[:], uint16(n))
	_, err = sc.Write(b[:n+2])
	return err
}

type corkedConn struct {
	net.Conn
	bufw   *bufio.Writer
	corked bool
	delay  time.Duration
	err    error
	lock   sync.Mutex
	once   sync.Once
}

func timedCork(c net.Conn, d time.Duration, bufSize int) net.Conn {
	return &corkedConn{
		Conn:   c,
		bufw:   bufio.NewWriterSize(c, bufSize),
		corked: true,
		delay:  d,
	}
}

func (w *corkedConn) Write(p []byte) (int, error) {
	w.lock.Lock()
	defer w.lock.Unlock()
	if w.err != nil {
		return 0, w.err
	}
	if w.corked {
		w.once.Do(func() {
			time.AfterFunc(w.delay, func() {
				w.lock.Lock()
				defer w.lock.Unlock()
				w.corked = false
				w.err = w.bufw.Flush()
			})
		})
		return w.bufw.Write(p)
	}
	return w.Conn.Write(p)
}
