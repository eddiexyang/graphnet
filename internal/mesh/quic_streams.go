package mesh

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eddiexyang/graphnet/internal/link"
	"github.com/eddiexyang/graphnet/internal/packetbuf"
	"github.com/eddiexyang/graphnet/internal/streamproxy"
)

const (
	qhopMaxChunk     = muxMaxData
	qhopAckThreshold = 64 << 10
	qhopFinEnd       = 1 << 0

	qerrHopReset     uint64 = 1
	qerrSessionAbort uint64 = 2
)

// QUICStreamsReady registers a Link whose native QUIC substreams are ready.
func (g *group) QUICStreamsReady(l *link.Link) {
	g.qmu.Lock()
	if g.qclosed {
		g.qmu.Unlock()
		return
	}
	if g.qlinks == nil {
		g.qlinks = map[*link.Link]map[uint64]*qhopStream{}
	}
	if g.qlinks[l] == nil {
		g.qlinks[l] = map[uint64]*qhopStream{}
	}
	g.qmu.Unlock()
	g.wakeSchedule()
	go func() {
		<-l.Done()
		g.quicLinkDone(l)
	}()
}

// LinkHealthy wakes the Edge scheduler when a QUIC-stream Link turns healthy.
func (g *group) LinkHealthy(*link.Link) {
	g.wakeSchedule()
}

func (g *group) maintainQUICStreams() {
	g.qmu.Lock()
	var active []*qhopStream
	for _, streams := range g.qlinks {
		for _, s := range streams {
			active = append(active, s)
		}
	}
	g.qmu.Unlock()
	for _, s := range active {
		s.mu.Lock()
		s.maybeSendAckLocked(true)
		remove := s.finishCheckLocked()
		s.mu.Unlock()
		if remove {
			g.removeQStream(s.l, s.id)
		}
	}
}

func (g *group) quicLinkDone(l *link.Link) {
	g.qmu.Lock()
	streams := g.qlinks[l]
	delete(g.qlinks, l)
	list := make([]*qhopStream, 0, len(streams))
	for _, s := range streams {
		list = append(list, s)
	}
	g.qmu.Unlock()
	for _, s := range list {
		s.failFromLink(errStreamReset)
	}
	g.wakeSchedule()
}

func (g *group) closeQUICStreams() {
	g.qmu.Lock()
	g.qclosed = true
	var list []*qhopStream
	for l, streams := range g.qlinks {
		delete(g.qlinks, l)
		for _, s := range streams {
			list = append(list, s)
		}
	}
	g.qmu.Unlock()
	for _, s := range list {
		s.failFromLink(net.ErrClosed)
	}
}

func (g *group) quicStreamCount() int {
	g.qmu.Lock()
	defer g.qmu.Unlock()
	total := 0
	for _, streams := range g.qlinks {
		total += len(streams)
	}
	return total
}

// quicStreamLink returns the Link to use for native QUIC streams when the
// Edge's active (or best healthy fallback) stream carrier uses native QUIC
// substreams. It returns nil when streams should use g.mux instead.
func (g *group) quicStreamLink() *link.Link {
	active := g.edge.Active()
	g.qmu.Lock()
	defer g.qmu.Unlock()
	if g.qclosed || len(g.qlinks) == 0 {
		return nil
	}
	if active != nil {
		select {
		case <-active.Done():
		default:
			if active.Healthy() && !active.RenewalDue() {
				if g.qlinks[active] != nil {
					return active
				}
				if active.StreamsReady() {
					return nil
				}
			}
		}
	}
	var best *link.Link
	for l := range g.qlinks {
		select {
		case <-l.Done():
			continue
		default:
		}
		if !l.Healthy() {
			continue
		}
		if best == nil || best.RenewalDue() && !l.RenewalDue() || best.RenewalDue() == l.RenewalDue() && l.Stats().RTTMillis < best.Stats().RTTMillis {
			best = l
		}
	}
	return best
}

func (g *group) openQUICStream(ctx context.Context, l *link.Link) (*qhopStream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sub, err := l.OpenSubstream(ctx, 3, true)
	if err != nil {
		return nil, err
	}
	s := newQHopStream(g, l, sub)
	g.qmu.Lock()
	if g.qclosed || g.qlinks[l] == nil {
		g.qmu.Unlock()
		s.cancel()
		sub.Close()
		return nil, link.ErrUnavailable
	}
	g.qlinks[l][sub.StreamID()] = s
	g.qmu.Unlock()
	return s, nil
}

func (g *group) AcceptQUICStream(l *link.Link, sub link.Substream, firstKind byte, firstBody []byte, firstOwner *packetbuf.Buffer) {
	s := newQHopStream(g, l, sub)
	switch firstKind {
	case link.QHopRecordData:
		if len(firstBody) > 0 {
			s.curBuf = firstOwner
			s.curData = firstBody
			l.AddRX(uint64(len(firstBody)))
			l.SawStream(time.Now())
			s.rx.Add(uint64(len(firstBody)))
		} else {
			firstOwner.Release()
		}
	case link.QHopRecordFin:
		peerEnd := len(firstBody) > 0 && firstBody[0]&qhopFinEnd != 0
		firstOwner.Release()
		s.finRecv = true
		s.finConsumed = true
		s.peerEnd = peerEnd
		l.SawStream(time.Now())
	default:
		firstOwner.Release()
		s.cancel()
		sub.Close()
		return
	}
	g.qmu.Lock()
	if g.qclosed || g.qlinks[l] == nil {
		g.qmu.Unlock()
		s.releaseCurrentLocked()
		s.cancel()
		sub.Close()
		return
	}
	g.qlinks[l][sub.StreamID()] = s
	g.qmu.Unlock()
	g.mesh.acceptConnStream(g, s)
}

func (g *group) ReceiveHopDelivered(l *link.Link, streamID, consumed, delivered uint64, finConsumed, explicit bool) {
	g.qmu.Lock()
	var s *qhopStream
	if streams := g.qlinks[l]; streams != nil {
		s = streams[streamID]
	}
	g.qmu.Unlock()
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.err != nil {
		s.mu.Unlock()
		return
	}
	before := s.peerDeliveredLocked()
	if consumed > s.peerConsumed {
		s.peerConsumed = consumed
	}
	if finConsumed {
		s.peerFin = true
	}
	if explicit {
		s.explicitPeer = true
		if delivered > s.peerDelivered {
			s.peerDelivered = delivered
		}
	}
	changed := s.session && s.peerDeliveredLocked() != before
	notify := s.onDelivered
	remove := s.finishCheckLocked()
	s.mu.Unlock()
	if remove {
		g.removeQStream(l, streamID)
	}
	if changed && notify != nil {
		notify()
	}
}

func (g *group) removeQStream(l *link.Link, id uint64) {
	g.qmu.Lock()
	if streams := g.qlinks[l]; streams != nil {
		delete(streams, id)
	}
	g.qmu.Unlock()
}

// qhopStream implements streamproxy.Hop directly over one native bidirectional
// QUIC stream, delegating reliability, windowing, and packet pacing to QUIC.
type qhopStream struct {
	g       *group
	l       *link.Link
	sub     link.Substream
	id      uint64
	ctx     context.Context
	cancel  context.CancelFunc
	writeMu sync.Mutex
	readMu  sync.Mutex
	rx, tx  atomic.Uint64

	mu          sync.Mutex
	sendNext    uint64
	writeClosed bool
	finOffset   uint64
	consumed    uint64
	ackConsumed uint64
	finRecv     bool
	finConsumed bool
	ackFin      bool
	peerEnd     bool
	peerAborted bool
	closed      bool
	err         error

	curBuf  *packetbuf.Buffer
	curData []byte

	dlMu     sync.Mutex
	writeTmr *time.Timer
	writeExp chan struct{}
	writeChg chan struct{}

	session       bool
	sendStart     uint64
	sendMark      uint64
	local         bool
	delivered     uint64
	ackDelivered  uint64
	explicitPeer  bool
	peerDelivered uint64
	peerConsumed  uint64
	peerFin       bool
	onDelivered   func()
	leftover      []byte
	keep          *streamproxy.Keep
}

func newQHopStream(g *group, l *link.Link, sub link.Substream) *qhopStream {
	ctx, cancel := context.WithCancel(g.ctx)
	return &qhopStream{
		g:      g,
		l:      l,
		sub:    sub,
		id:     sub.StreamID(),
		ctx:    ctx,
		cancel: cancel,
	}
}

func (s *qhopStream) releaseCurrentLocked() {
	if s.curBuf != nil {
		s.curBuf.Release()
		s.curBuf = nil
	}
	s.curData = nil
}

func (s *qhopStream) SetReadDeadline(t time.Time) error {
	return s.sub.SetReadDeadline(t)
}

func (s *qhopStream) SetWriteDeadline(t time.Time) error {
	_ = s.sub.SetWriteDeadline(t)
	s.dlMu.Lock()
	defer s.dlMu.Unlock()
	if s.writeTmr != nil {
		s.writeTmr.Stop()
		s.writeTmr = nil
	}
	s.writeExp = nil
	if !t.IsZero() {
		exp := make(chan struct{})
		s.writeExp = exp
		if d := time.Until(t); d <= 0 {
			close(exp)
		} else {
			s.writeTmr = time.AfterFunc(d, func() { close(exp) })
		}
	}
	if s.writeChg != nil {
		close(s.writeChg)
		s.writeChg = nil
	}
	return nil
}

func (s *qhopStream) writeDeadlineChans() (exp, chg chan struct{}) {
	s.dlMu.Lock()
	defer s.dlMu.Unlock()
	if s.writeChg == nil {
		s.writeChg = make(chan struct{})
	}
	return s.writeExp, s.writeChg
}

func (s *qhopStream) Buffered() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.curData)
}

func (s *qhopStream) ReadWindow() (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	return s.fillLocked()
}

func (s *qhopStream) fillLocked() (int, error) {
	for {
		s.mu.Lock()
		if len(s.curData) > 0 {
			n := len(s.curData)
			s.mu.Unlock()
			return n, nil
		}
		if s.finRecv {
			s.finConsumed = true
			s.maybeSendAckLocked(true)
			remove := s.finishCheckLocked()
			s.mu.Unlock()
			if remove {
				s.g.removeQStream(s.l, s.id)
			}
			return 0, io.EOF
		}
		if s.err != nil {
			err := s.err
			s.mu.Unlock()
			return 0, err
		}
		s.mu.Unlock()

		kind, body, owner, err := s.sub.ReceiveOwnedRecord()
		if err != nil {
			owner.Release()
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return 0, os.ErrDeadlineExceeded
			}
			code, hasCode := s.l.SubstreamErrorCode(err)
			s.mu.Lock()
			if hasCode && code == qerrSessionAbort {
				s.peerAborted = true
			}
			if s.err == nil {
				s.failLocked(errStreamReset, false, 0)
			}
			retErr := s.err
			s.mu.Unlock()
			s.g.removeQStream(s.l, s.id)
			return 0, retErr
		}
		s.l.SawStream(time.Now())
		switch kind {
		case link.QHopRecordData:
			if len(body) == 0 {
				owner.Release()
				continue
			}
			s.l.AddRX(uint64(len(body)))
			s.rx.Add(uint64(len(body)))
			s.mu.Lock()
			if s.err != nil {
				err := s.err
				s.mu.Unlock()
				owner.Release()
				return 0, err
			}
			s.curBuf = owner
			s.curData = body
			n := len(body)
			s.mu.Unlock()
			return n, nil
		case link.QHopRecordFin:
			peerEnd := len(body) > 0 && body[0]&qhopFinEnd != 0
			owner.Release()
			s.mu.Lock()
			s.finRecv = true
			s.finConsumed = true
			s.peerEnd = peerEnd
			s.maybeSendAckLocked(true)
			remove := s.finishCheckLocked()
			s.mu.Unlock()
			if remove {
				s.g.removeQStream(s.l, s.id)
			}
			return 0, io.EOF
		default:
			owner.Release()
			s.mu.Lock()
			s.failLocked(errStreamReset, true, qerrHopReset)
			s.mu.Unlock()
			s.g.removeQStream(s.l, s.id)
			return 0, errStreamReset
		}
	}
}

func (s *qhopStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if _, err := s.fillLocked(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	n := copy(p, s.curData)
	s.curData = s.curData[n:]
	if len(s.curData) == 0 {
		s.releaseCurrentLocked()
	}
	s.consumed += uint64(n)
	s.maybeSendAckLocked(false)
	s.mu.Unlock()
	return n, nil
}

func (s *qhopStream) RelayTo(hop streamproxy.Hop) (int64, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	var total int64
	for {
		if _, err := s.fillLocked(); err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
		s.mu.Lock()
		data := s.curData
		buf := s.curBuf
		s.curData = nil
		s.curBuf = nil
		s.mu.Unlock()
		if len(data) == 0 {
			buf.Release()
			continue
		}
		_, writeErr := hop.Write(data)
		buf.Release()
		if s.g != nil && s.g.mesh != nil {
			s.g.mesh.relayCopied.Add(uint64(len(data)))
		}
		if writeErr != nil {
			return total, writeErr
		}
		s.mu.Lock()
		s.consumed += uint64(len(data))
		s.maybeSendAckLocked(false)
		s.mu.Unlock()
		total += int64(len(data))
	}
}

func (s *qhopStream) waitKeep(need int) (int, error) {
	s.mu.Lock()
	keep := s.keep
	s.mu.Unlock()
	if keep == nil {
		return math.MaxInt, nil
	}
	for {
		exp, chg := s.writeDeadlineChans()
		if exp == nil {
			return keep.Wait(s.ctx, need)
		}
		select {
		case <-exp:
			return 0, os.ErrDeadlineExceeded
		default:
		}
		waitCtx, cancel := context.WithCancel(s.ctx)
		var expired atomic.Bool
		var changed atomic.Bool
		done := make(chan struct{})
		go func() {
			defer close(done)
			select {
			case <-exp:
				expired.Store(true)
				cancel()
			case <-chg:
				changed.Store(true)
				cancel()
			case <-waitCtx.Done():
			}
		}()
		n, err := keep.Wait(waitCtx, need)
		cancel()
		<-done
		if err == nil {
			return n, nil
		}
		if expired.Load() {
			return 0, os.ErrDeadlineExceeded
		}
		if changed.Load() && s.ctx.Err() == nil {
			continue
		}
		return 0, err
	}
}

func (s *qhopStream) writeOneChunk(chunk []byte) (bool, error) {
	s.mu.Lock()
	if s.err != nil {
		err := s.err
		s.mu.Unlock()
		return false, err
	}
	if s.writeClosed {
		s.mu.Unlock()
		return false, io.ErrClosedPipe
	}
	keep := s.keep
	s.mu.Unlock()

	if exp, _ := s.writeDeadlineChans(); exp != nil {
		select {
		case <-exp:
			return false, os.ErrDeadlineExceeded
		default:
		}
	}

	committed := false
	if keep != nil {
		// Commit to session retention before bytes can reach the wire so the
		// far end can never observe bytes outside Keep's bounds.
		buf := packetbuf.Get(muxDataHeader + len(chunk))
		s.mu.Lock()
		if s.err != nil {
			err := s.err
			s.mu.Unlock()
			buf.Release()
			return false, err
		}
		payload := buf.Data[muxDataHeader : muxDataHeader+len(chunk)]
		copy(payload, chunk)
		keep.Add(payload, buf, muxDataHeader)
		s.sendNext += uint64(len(chunk))
		s.mu.Unlock()
		buf.Release()
		committed = true
	} else {
		s.mu.Lock()
		if s.err != nil {
			err := s.err
			s.mu.Unlock()
			return false, err
		}
		s.sendNext += uint64(len(chunk))
		s.mu.Unlock()
	}

	sentAny, err := s.sub.SendRecord(link.QHopRecordData, chunk)
	if err != nil {
		if keep == nil && !sentAny && errors.Is(err, os.ErrDeadlineExceeded) {
			s.mu.Lock()
			s.sendNext -= uint64(len(chunk))
			s.mu.Unlock()
			return false, os.ErrDeadlineExceeded
		}
		code, hasCode := s.l.SubstreamErrorCode(err)
		s.mu.Lock()
		if hasCode && code == qerrSessionAbort {
			s.peerAborted = true
		}
		if s.err == nil {
			s.failLocked(errStreamReset, true, qerrHopReset)
		}
		retErr := s.err
		s.mu.Unlock()
		s.g.removeQStream(s.l, s.id)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return committed, os.ErrDeadlineExceeded
		}
		return committed, retErr
	}
	s.l.AddTX(uint64(len(chunk)))
	s.tx.Add(uint64(len(chunk)))
	return true, nil
}

func (s *qhopStream) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	written := 0
	for len(p) > 0 {
		room, err := s.waitKeep(1)
		if err != nil {
			return written, s.errOr(err)
		}
		n := min(len(p), room, qhopMaxChunk)
		committed, err := s.writeOneChunk(p[:n])
		if committed {
			written += n
		}
		if err != nil {
			return written, err
		}
		p = p[n:]
	}
	return written, nil
}

type qhopSliceWriter struct {
	buf []byte
	n   int
}

func (w *qhopSliceWriter) Room() int { return len(w.buf) - w.n }

func (w *qhopSliceWriter) Write(p []byte) (int, error) {
	c := copy(w.buf[w.n:], p)
	w.n += c
	if c < len(p) {
		return c, io.ErrShortWrite
	}
	return c, nil
}

func (s *qhopStream) ReadFrom(src io.Reader) (int64, error) {
	reader, ok := src.(interface{ ReadInto(io.Writer) (int, error) })
	if !ok {
		return io.CopyBuffer(muxWriterOnly{s}, src, make([]byte, 64*1024))
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	var scratch [qhopMaxChunk]byte
	var total int64
	for {
		room, err := s.waitKeep(1)
		if err != nil {
			return total, s.errOr(err)
		}
		limit := min(room, qhopMaxChunk)
		w := qhopSliceWriter{buf: scratch[:limit]}
		n, readErr := reader.ReadInto(&w)
		if n > 0 {
			committed, writeErr := s.writeOneChunk(scratch[:n])
			if committed {
				total += int64(n)
			} else {
				s.mu.Lock()
				s.leftover = append(s.leftover, scratch[:n]...)
				s.mu.Unlock()
			}
			if writeErr != nil {
				return total, writeErr
			}
		}
		if readErr == io.EOF {
			return total, nil
		}
		if readErr != nil {
			return total, readErr
		}
		if n == 0 {
			return total, io.ErrNoProgress
		}
	}
}

func (s *qhopStream) CloseWrite() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	if s.err != nil || s.writeClosed {
		err := s.err
		s.mu.Unlock()
		return err
	}
	s.writeClosed, s.finOffset = true, s.sendNext
	var flags byte
	if s.session {
		flags |= qhopFinEnd
	}
	s.mu.Unlock()

	var finBody [1]byte
	finBody[0] = flags
	if _, err := s.sub.SendRecord(link.QHopRecordFin, finBody[:]); err != nil {
		code, hasCode := s.l.SubstreamErrorCode(err)
		s.mu.Lock()
		if hasCode && code == qerrSessionAbort {
			s.peerAborted = true
		}
		if s.err == nil {
			s.failLocked(errStreamReset, true, qerrHopReset)
		}
		retErr := s.err
		s.mu.Unlock()
		s.g.removeQStream(s.l, s.id)
		return retErr
	}
	_ = s.sub.CloseWrite()
	return nil
}

func (s *qhopStream) Close() error {
	s.mu.Lock()
	if s.err == nil && !s.closed {
		s.closed = true
		if !(s.writeClosed && s.finRecv && len(s.curData) == 0) {
			s.failLocked(net.ErrClosed, true, qerrHopReset)
			s.mu.Unlock()
			s.g.removeQStream(s.l, s.id)
			return nil
		}
		s.maybeSendAckLocked(true)
	}
	remove := s.finishCheckLocked()
	s.mu.Unlock()
	if remove {
		s.g.removeQStream(s.l, s.id)
	}
	return nil
}

func (s *qhopStream) Abort() {
	s.mu.Lock()
	if s.err == nil {
		s.failLocked(errStreamReset, true, qerrHopReset)
		s.mu.Unlock()
		s.g.removeQStream(s.l, s.id)
		return
	}
	s.mu.Unlock()
}

func (s *qhopStream) AbortSession() {
	s.mu.Lock()
	if s.err == nil {
		s.failLocked(errStreamReset, true, qerrSessionAbort)
		s.mu.Unlock()
		s.g.removeQStream(s.l, s.id)
		return
	}
	s.mu.Unlock()
}

func (s *qhopStream) failFromLink(err error) {
	s.mu.Lock()
	s.failLocked(err, true, qerrHopReset)
	s.mu.Unlock()
}

// finishCheckLocked reports whether a cleanly closed stream finished all
// pending delivery confirmations and can be removed from the Link map.
func (s *qhopStream) finishCheckLocked() bool {
	if !s.closed || !s.writeClosed || !s.finRecv || len(s.curData) > 0 {
		return false
	}
	if s.session && !s.peerFin && (!s.explicitPeer || s.peerDelivered <= s.sendStart+s.finOffset-s.sendMark) {
		return false
	}
	s.failLocked(net.ErrClosed, false, 0)
	_ = s.sub.Close()
	return true
}

func (s *qhopStream) failLocked(err error, cancelSub bool, code uint64) {
	if s.err != nil {
		return
	}
	s.err = err
	s.releaseCurrentLocked()
	s.cancel()
	s.dlMu.Lock()
	if s.writeTmr != nil {
		s.writeTmr.Stop()
		s.writeTmr = nil
	}
	s.dlMu.Unlock()
	if cancelSub {
		s.sub.Cancel(code)
	}
}

func (s *qhopStream) errOr(fallback error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	return fallback
}

func (s *qhopStream) maybeSendAckLocked(force bool) {
	if !s.session || s.err != nil {
		return
	}
	if s.local {
		finNow := s.finConsumed && !s.ackFin
		step := s.consumed >= s.ackConsumed && s.consumed-s.ackConsumed >= qhopAckThreshold
		if !force && !finNow && !step {
			return
		}
		if !finNow && s.consumed == s.ackConsumed {
			return
		}
		s.ackConsumed = s.consumed
		if s.finConsumed {
			s.ackFin = true
		}
		s.l.SendHopDelivered(s.id, s.consumed, 0, s.finConsumed, false)
		return
	}
	if !s.local {
		finNow := s.finConsumed && !s.ackFin
		if s.delivered <= s.ackDelivered && !finNow {
			return
		}
		if !force && !finNow && s.delivered-s.ackDelivered < qhopAckThreshold {
			return
		}
		s.ackDelivered = s.delivered
		if s.finConsumed {
			s.ackFin = true
		}
		s.l.SendHopDelivered(s.id, s.consumed, s.delivered, s.finConsumed, true)
		return
	}
}

func (s *qhopStream) Bytes() (rx, tx uint64) { return s.rx.Load(), s.tx.Load() }

func (s *qhopStream) Begin(send uint64) {
	s.mu.Lock()
	s.session = true
	s.sendStart, s.sendMark = send, s.sendNext
	s.maybeSendAckLocked(true)
	s.mu.Unlock()
}

func (s *qhopStream) DeliverLocal() {
	s.mu.Lock()
	s.local = true
	if s.session {
		s.maybeSendAckLocked(true)
	}
	s.mu.Unlock()
}

func (s *qhopStream) SetDelivered(e uint64) {
	s.mu.Lock()
	if e <= s.delivered || s.err != nil {
		s.mu.Unlock()
		return
	}
	s.session = true
	s.delivered = e
	s.maybeSendAckLocked(false)
	s.mu.Unlock()
}

func (s *qhopStream) PeerDelivered() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peerDeliveredLocked()
}

func (s *qhopStream) peerDeliveredLocked() uint64 {
	if s.explicitPeer {
		return s.peerDelivered
	}
	if s.peerConsumed < s.sendMark {
		return s.sendStart
	}
	e := s.sendStart + s.peerConsumed - s.sendMark
	if s.writeClosed && s.peerFin && s.peerConsumed == s.finOffset {
		e++
	}
	return e
}

func (s *qhopStream) PeerEnded() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeClosed && s.peerDeliveredLocked() > s.sendStart+s.finOffset-s.sendMark
}

func (s *qhopStream) Done() <-chan struct{} { return s.ctx.Done() }

func (s *qhopStream) OnDelivered(notify func()) {
	s.mu.Lock()
	s.onDelivered = notify
	s.mu.Unlock()
}

func (s *qhopStream) SetRetention(k *streamproxy.Keep) {
	s.mu.Lock()
	s.keep = k
	s.mu.Unlock()
}

func (s *qhopStream) Leftover() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	left := s.leftover
	s.leftover = nil
	return left
}

func (s *qhopStream) Ended() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peerEnd
}

func (s *qhopStream) Aborted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peerAborted
}
