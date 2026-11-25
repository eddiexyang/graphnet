// Package streamproxy terminates TCP at access boundaries and relays bytes.
package streamproxy

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"sync"

	"github.com/eddiexyang/graphnet/internal/model"
)

const SetupLimit = 512

// MaxHandshakes bounds connections in their handshake, as the kernel's
// tcp_max_syn_backlog does; established connections are not limited.
const MaxHandshakes = 256

type Request struct {
	Network     model.ID       `json:"network"`
	Source      model.ID       `json:"source"`
	Destination model.ID       `json:"destination"`
	From        netip.AddrPort `json:"from"`
	To          netip.AddrPort `json:"to"`
	Hops        uint8          `json:"hops"`
	// Seq is the SYN's sequence number, which an ICMP error quotes when a hop
	// ends the connection's hop limit.
	Seq uint32 `json:"seq,omitempty"`
	// A chain of a resumable session names the session and its generation;
	// its downstream bytes start at Down and its upstream bytes at Up. See
	// session.go.
	Conn SessionID `json:"conn,omitzero"`
	Gen  uint32    `json:"gen,omitempty"`
	Down uint64    `json:"down,omitempty"`
	Up   uint64    `json:"up,omitempty"`
	// At asks the egress to answer StatusOKAt with what it has read, so the
	// ingress resends only past it. A relay that predates it drops it, and the
	// egress then answers StatusOK.
	At bool `json:"at,omitempty"`
}

// Resumable reports whether the request opens a chain of a session.
func (r Request) Resumable() bool { return r.Conn != SessionID{} }

func (r Request) Validate() error {
	for _, id := range []model.ID{r.Network, r.Source, r.Destination} {
		if err := id.Validate(); err != nil {
			return err
		}
	}
	if r.Hops == 0 || !r.From.IsValid() || !r.To.IsValid() || r.From.Port() == 0 || r.To.Port() == 0 ||
		!r.From.Addr().IsGlobalUnicast() || !r.To.Addr().IsGlobalUnicast() ||
		r.From.Addr().Is4In6() || r.To.Addr().Is4In6() || r.From.Addr().Zone() != "" || r.To.Addr().Zone() != "" ||
		r.From.Addr().BitLen() != r.To.Addr().BitLen() {
		return errors.New("invalid TCP stream destination or hop limit")
	}
	return nil
}
func WriteRequest(w io.Writer, r Request) error {
	if err := r.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(raw) > SetupLimit {
		return errors.New("stream request too large")
	}
	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(len(raw)))
	if err := writeAll(w, prefix[:]); err != nil {
		return err
	}
	return writeAll(w, raw)
}
func ReadRequest(r io.Reader) (Request, error) {
	var request Request
	var prefix [2]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return request, err
	}
	size := int(binary.BigEndian.Uint16(prefix[:]))
	if size == 0 || size > SetupLimit {
		return request, errors.New("invalid stream request size")
	}
	raw := make([]byte, size)
	if _, err := io.ReadFull(r, raw); err != nil {
		return request, err
	}
	if err := json.Unmarshal(raw, &request); err != nil {
		return request, err
	}
	return request, request.Validate()
}
func writeAll(w io.Writer, raw []byte) error {
	for len(raw) > 0 {
		n, err := w.Write(raw)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(raw) {
			return io.ErrShortWrite
		}
		raw = raw[n:]
	}
	return nil
}

type Conn interface {
	io.ReadWriteCloser
	CloseWrite() error
}

func During(ctx context.Context, c Conn, operation func() error) error {
	stop := context.AfterFunc(ctx, func() { c.Close() })
	err := operation()
	if !stop() && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// Relay propagates write-half closes so a server can respond after request EOF.
// Errors and cancellation interrupt both directions; there is no byte replay.
func Relay(ctx context.Context, a, b Conn) error {
	return relay(ctx, a, b, nil)
}

func relay(ctx context.Context, a, b Conn, onError func(error)) error {
	closeBoth := sync.OnceFunc(func() { a.Close(); b.Close() })
	abortBoth := func() {
		for _, conn := range []Conn{a, b} {
			if tcp, ok := conn.(interface{ Abort() }); ok {
				tcp.Abort()
			}
		}
		closeBoth()
	}
	stop := context.AfterFunc(ctx, abortBoth)
	defer stop()
	defer closeBoth()
	errs := make(chan error, 2)
	copyTo := func(dst, src Conn) {
		_, err := relayCopy(dst, src)
		if err == nil {
			err = dst.CloseWrite()
		}
		if err != nil {
			if onError != nil {
				onError(err)
			}
			abortBoth()
		}
		errs <- err
	}
	go copyTo(a, b)
	go copyTo(b, a)
	err := errors.Join(<-errs, <-errs)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

var relayBufPool = sync.Pool{New: func() any { b := make([]byte, 64*1024); return &b }}

func relayCopy(dst io.Writer, src io.Reader) (int64, error) {
	if wt, ok := src.(io.WriterTo); ok {
		return wt.WriteTo(dst)
	}
	if rf, ok := dst.(io.ReaderFrom); ok {
		return rf.ReadFrom(src)
	}
	if rw, ok := src.(interface{ ReadWindow() (int, error) }); ok {
		var total int64
		for {
			avail, err := rw.ReadWindow()
			if err == io.EOF {
				return total, nil
			}
			if err != nil {
				return total, err
			}
			if avail <= 0 {
				continue
			}
			bp := relayBufPool.Get().(*[]byte)
			buf := (*bp)[:min(len(*bp), avail)]
			n, rerr := src.Read(buf)
			if n > 0 {
				wn, werr := dst.Write(buf[:n])
				total += int64(wn)
				if werr != nil {
					relayBufPool.Put(bp)
					return total, werr
				}
				if wn != n {
					relayBufPool.Put(bp)
					return total, io.ErrShortWrite
				}
			}
			relayBufPool.Put(bp)
			if rerr == io.EOF {
				return total, nil
			}
			if rerr != nil {
				return total, rerr
			}
		}
	}
	bp := relayBufPool.Get().(*[]byte)
	defer relayBufPool.Put(bp)
	return io.CopyBuffer(dst, src, *bp)
}
