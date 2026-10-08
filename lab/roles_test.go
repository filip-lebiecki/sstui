//go:build lab

package lab

import (
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// roleEnv tells TestMain that the binary was re-executed to run a role.
const roleEnv = "SSTUI_LAB_ROLE"

// runRole runs one workload until it's killed. Roles that only set up state
// (hangup) return once it's in place.
//
//	sink ADDR                 accept connections and read everything
//	send ADDR [N [CC]]        N connections (default 1) writing as fast as they can,
//	                          with congestion control CC (default: the system's)
//	stall ADDR                accept connections and never read (zero window)
//	backlog ADDR N            listen with an accept queue of N, never accept
//	hold ADDR N               open N connections and keep them
//	noclose ADDR              accept connections and never close them
//	hangup ADDR N             open N connections, then close them
//	slowaccept ADDR N MS      listen with an accept queue of N, accept (and close)
//	                          one connection every MS ms
//	burst ADDR N MS           every MS ms, open N connections at once, then close them
//	reqserver ADDR SIZE       answer every request byte with SIZE bytes
//	reqclient ADDR SIZE N     N connections, each asking for SIZE bytes at random intervals
func runRole(args []string) error {
	arg := func(i int) string {
		if i < len(args) {
			return args[i]
		}
		return ""
	}
	num := func(i int) int {
		n, err := strconv.Atoi(arg(i))
		if err != nil {
			panic(fmt.Sprintf("role %s: argument %d: %v", arg(0), i, err))
		}
		return n
	}
	switch arg(0) {
	case "sink":
		return serve(arg(1), func(c net.Conn) { io.Copy(io.Discard, c) })
	case "send":
		n := 1
		if arg(2) != "" {
			n = num(2)
		}
		errc := make(chan error, n)
		for range n {
			go func() {
				c, err := dialCC(arg(1), arg(3))
				if err != nil {
					errc <- err
					return
				}
				buf := make([]byte, 64<<10)
				for {
					if _, err := c.Write(buf); err != nil {
						errc <- err
						return
					}
				}
			}()
		}
		return <-errc
	case "stall":
		return serve(arg(1), keep)
	case "backlog":
		return listenNoAccept(arg(1), num(2))
	case "hold":
		for range num(2) {
			// Past the accept queue the handshake never completes; keep
			// trying in the background like a client would.
			go func() {
				if c, err := dial(arg(1)); err == nil {
					keep(c)
				}
			}()
		}
		sleepForever()
	case "noclose":
		return serve(arg(1), keep)
	case "hangup":
		var conns []net.Conn
		for range num(2) {
			c, err := dial(arg(1))
			if err != nil {
				return err
			}
			conns = append(conns, c)
		}
		for _, c := range conns {
			c.Close()
		}
		return nil
	case "slowaccept":
		fd, err := listenBacklog(arg(1), num(2))
		if err != nil {
			return err
		}
		for {
			time.Sleep(time.Duration(num(3)) * time.Millisecond)
			nfd, _, err := syscall.Accept(fd)
			if err != nil {
				return err
			}
			syscall.Close(nfd)
		}
	case "burst":
		for {
			var wg sync.WaitGroup
			for range num(2) {
				wg.Add(1)
				go func() {
					defer wg.Done()
					// A refused handshake is retried by the kernel (SYN
					// backoff); give up after a few seconds like a client.
					if c, err := net.DialTimeout("tcp", arg(1), 4*time.Second); err == nil {
						c.Close()
					}
				}()
			}
			wg.Wait()
			time.Sleep(time.Duration(num(3)) * time.Millisecond)
		}
	case "reqserver":
		resp := make([]byte, num(2))
		return serve(arg(1), func(c net.Conn) {
			req := make([]byte, 1)
			for {
				if _, err := c.Read(req); err != nil {
					return
				}
				if _, err := c.Write(resp); err != nil {
					return
				}
			}
		})
	case "reqclient":
		size := num(2)
		for range num(3) {
			go func() {
				c, err := dial(arg(1))
				if err != nil {
					return
				}
				buf := make([]byte, 64<<10)
				for {
					if _, err := c.Write([]byte{1}); err != nil {
						return
					}
					for got := 0; got < size; {
						n, err := c.Read(buf)
						if err != nil {
							return
						}
						got += n
					}
					time.Sleep(time.Duration(20+rand.IntN(280)) * time.Millisecond)
				}
			}()
		}
		sleepForever()
	}
	return fmt.Errorf("unknown role %q", arg(0))
}

var (
	keptMu sync.Mutex
	kept   []net.Conn
)

// keep holds a connection open for the life of the process without using it:
// an unreferenced net.Conn is closed by its finalizer once the GC finds it.
func keep(c net.Conn) {
	keptMu.Lock()
	kept = append(kept, c)
	keptMu.Unlock()
}

// serve accepts connections on addr and runs handle for each in its own
// goroutine.
func serve(addr string, handle func(net.Conn)) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go handle(c)
	}
}

// dial connects to addr, retrying while the server's role is still starting.
func dial(addr string) (net.Conn, error) { return dialCC(addr, "") }

// dialCC is dial with congestion control cc ("" for the system default).
func dialCC(addr, cc string) (net.Conn, error) {
	d := net.Dialer{}
	if cc != "" {
		d.Control = func(_, _ string, rc syscall.RawConn) error {
			var serr error
			if err := rc.Control(func(fd uintptr) {
				serr = syscall.SetsockoptString(int(fd), syscall.IPPROTO_TCP, syscall.TCP_CONGESTION, cc)
			}); err != nil {
				return err
			}
			return serr
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := d.Dial("tcp", addr)
		if err == nil || time.Now().After(deadline) {
			return c, err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// listenNoAccept listens with an explicit backlog and never accepts, so the
// accept queue fills.
func listenNoAccept(addr string, backlog int) error {
	if _, err := listenBacklog(addr, backlog); err != nil {
		return err
	}
	sleepForever()
	return nil
}

// listenBacklog listens on addr with an explicit accept-queue length
// (net.Listen always uses somaxconn) and returns the socket.
func listenBacklog(addr string, backlog int) (int, error) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return 0, err
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return 0, err
	}
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return 0, err
	}
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Port: int(ap.Port()), Addr: ap.Addr().As4()}); err != nil {
		return 0, err
	}
	return fd, syscall.Listen(fd, backlog)
}

// sleepForever blocks without tripping the runtime's deadlock detector (a
// bare select{} in a process with no other goroutines would).
func sleepForever() {
	for {
		time.Sleep(time.Hour)
	}
}
