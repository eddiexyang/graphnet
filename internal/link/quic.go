package link

import (
	"context"
	"encoding/binary"
	"time"

	"github.com/eddiexyang/graphnet/internal/packet"
	"github.com/eddiexyang/graphnet/internal/packetbuf"
)

const (
	// Stream 0 capability announcement confirming native QUIC substreams.
	quicStreamHelloMessage = 25
	// Stream 0 coalesced session delivery progress for a native QUIC hop stream:
	// [kind][flags][8B streamID][8B consumed][8B delivered].
	hopDeliveredMessage = 26
	hopDeliveredSize    = 26

	hopFlagFin      = 1 << 0
	hopFlagExplicit = 1 << 1

	// Substream record kinds: packet substream uses 1..2; hop streams use 10..11.
	qsubKindPackets     = 1
	qsubKindPacketFrame = 2

	QHopRecordData = 10
	QHopRecordFin  = 11
)

// Substream is one ordered, AEAD-authenticated bidirectional stream multiplexed
// alongside Stream 0 on the same Link connection.
type Substream interface {
	StreamID() uint64
	SendRecord(kind byte, body []byte) (bool, error)
	SendRecordBatch(kind byte, bodies [][]byte) error
	ReceiveOwnedRecord() (kind byte, body []byte, owner *packetbuf.Buffer, err error)
	SetPriority(urgency int8, incremental bool)
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	CloseWrite() error
	Cancel(code uint64)
	Close() error
}

// SubstreamProvider supplies native transport substreams for a QUIC Link.
type SubstreamProvider struct {
	Open      func(ctx context.Context, urgency int8, incremental bool) (Substream, error)
	Accept    func(ctx context.Context) (Substream, error)
	ErrorCode func(error) (uint64, bool)
}

// QUICStreamHandler manages per-hop native QUIC byte streams on an Edge.
type QUICStreamHandler interface {
	QUICStreamsReady(*Link)
	AcceptQUICStream(l *Link, sub Substream, firstKind byte, firstBody []byte, firstOwner *packetbuf.Buffer)
	ReceiveHopDelivered(l *Link, streamID, consumed, delivered uint64, finConsumed, explicit bool)
}

type hopAckEntry struct {
	consumed    uint64
	delivered   uint64
	finConsumed bool
	explicit    bool
	queued      bool
}

func (l *Link) QUICStreams() bool { return l.quicStreams.Load() }

func (l *Link) OpenSubstream(ctx context.Context, urgency int8, incremental bool) (Substream, error) {
	if l.options.Substreams == nil || l.options.Substreams.Open == nil {
		return nil, ErrUnavailable
	}
	return l.options.Substreams.Open(ctx, urgency, incremental)
}

func (l *Link) SubstreamErrorCode(err error) (uint64, bool) {
	if l.options.Substreams == nil || l.options.Substreams.ErrorCode == nil {
		return 0, false
	}
	return l.options.Substreams.ErrorCode(err)
}

func (l *Link) AddRX(n uint64) { l.rx.Add(n) }
func (l *Link) AddTX(n uint64) { l.tx.Add(n) }
func (l *Link) SawStream(now time.Time) {
	l.sawStream(now)
}

func (l *Link) notifyPacketSub() {
	select {
	case l.packetSubWake <- struct{}{}:
	default:
	}
}

// SendHopDelivered coalesces a native QUIC hop stream's session delivery state
// for transmission on Stream 0 without blocking or dropping the latest offset.
func (l *Link) SendHopDelivered(streamID, consumed, delivered uint64, finConsumed, explicit bool) {
	l.hopAckMu.Lock()
	if l.hopAcks == nil {
		l.hopAcks = map[uint64]hopAckEntry{}
	}
	cur := l.hopAcks[streamID]
	if consumed > cur.consumed {
		cur.consumed = consumed
	}
	if finConsumed {
		cur.finConsumed = true
	}
	if explicit {
		cur.explicit = true
		if delivered > cur.delivered {
			cur.delivered = delivered
		}
	}
	if !cur.queued {
		cur.queued = true
		l.hopAckOrder = append(l.hopAckOrder, streamID)
	}
	l.hopAcks[streamID] = cur
	l.hopAckMu.Unlock()
	select {
	case l.hopAckWake <- struct{}{}:
	default:
	}
}

func (l *Link) pullHopAcks(dst [][]byte) int {
	l.hopAckMu.Lock()
	defer l.hopAckMu.Unlock()
	n := 0
	for n < len(dst) && len(l.hopAckOrder) > 0 {
		id := l.hopAckOrder[0]
		l.hopAckOrder = l.hopAckOrder[1:]
		entry, ok := l.hopAcks[id]
		delete(l.hopAcks, id)
		if !ok {
			continue
		}
		raw := make([]byte, hopDeliveredSize)
		raw[0] = hopDeliveredMessage
		var flags byte
		if entry.finConsumed {
			flags |= hopFlagFin
		}
		if entry.explicit {
			flags |= hopFlagExplicit
		}
		raw[1] = flags
		binary.BigEndian.PutUint64(raw[2:10], id)
		binary.BigEndian.PutUint64(raw[10:18], entry.consumed)
		binary.BigEndian.PutUint64(raw[18:26], entry.delivered)
		dst[n] = raw
		n++
	}
	if len(l.hopAckOrder) > 0 {
		select {
		case l.hopAckWake <- struct{}{}:
		default:
		}
	}
	return n
}

func (l *Link) startQUICSubstreams(openPacket bool) {
	l.wg.Add(1)
	go l.acceptSubstreamsLoop()
	if openPacket {
		l.wg.Add(1)
		go l.openPacketSubstream()
	}
}

func (l *Link) openPacketSubstream() {
	defer l.wg.Done()
	sub, err := l.OpenSubstream(l.ctx, 1, false)
	if err != nil {
		return
	}
	if _, err := sub.SendRecord(qsubKindPackets, nil); err != nil {
		sub.Close()
		return
	}
	l.attachPacketSubstream(sub)
}

func (l *Link) acceptSubstreamsLoop() {
	defer l.wg.Done()
	if l.options.Substreams == nil || l.options.Substreams.Accept == nil {
		return
	}
	for {
		sub, err := l.options.Substreams.Accept(l.ctx)
		if err != nil {
			return
		}
		l.wg.Add(1)
		go func(sub Substream) {
			defer l.wg.Done()
			// Bound initial record wait so an idle uninitialized stream cannot linger.
			_ = sub.SetReadDeadline(time.Now().Add(10 * time.Second))
			kind, body, owner, err := sub.ReceiveOwnedRecord()
			_ = sub.SetReadDeadline(time.Time{})
			if err != nil {
				owner.Release()
				sub.Close()
				return
			}
			switch kind {
			case qsubKindPackets:
				owner.Release()
				if len(body) != 0 || !l.options.Accepted {
					sub.Close()
					return
				}
				sub.SetPriority(1, false)
				l.attachPacketSubstream(sub)
			case QHopRecordData, QHopRecordFin:
				sub.SetPriority(3, true)
				if l.options.QUICStreamHandler == nil {
					owner.Release()
					sub.Close()
					return
				}
				l.options.QUICStreamHandler.AcceptQUICStream(l, sub, kind, body, owner)
			default:
				owner.Release()
				sub.Close()
			}
		}(sub)
	}
}

func (l *Link) attachPacketSubstream(sub Substream) {
	if !l.packetSubSet.CompareAndSwap(false, true) {
		sub.Close()
		return
	}
	context.AfterFunc(l.ctx, func() { _ = sub.Close() })
	l.packetSubReady.Store(true)
	l.queueMu.Lock()
	hasData := l.dataCount > 0
	l.queueMu.Unlock()
	if hasData {
		l.notifyPacketSub()
	}
	l.wg.Add(2)
	go l.packetWriteLoop(sub)
	go l.packetReadLoop(sub)
}

func (l *Link) packetWriteLoop(sub Substream) {
	defer l.wg.Done()
	defer sub.Close()
	var messages [packetbuf.BatchSize][]byte
	var owners [packetbuf.BatchSize]*packetbuf.Buffer
	defer func() {
		packetbuf.ReleaseAll(owners[:])
	}()
	for {
		select {
		case <-l.ctx.Done():
			return
		case <-l.packetSubWake:
		}
		for {
			count := 0
			l.queueMu.Lock()
			for l.dataCount > 0 && count < len(messages) {
				data := l.takeData()
				if data.generation%2 == 0 || data.generation != l.dataGeneration.Load() {
					l.dropped.Add(1)
					data.buffer.Release()
					continue
				}
				messages[count], owners[count] = data.raw, data.buffer
				count++
			}
			more := l.dataCount > 0
			l.queueMu.Unlock()
			if count == 0 {
				break
			}
			err := sub.SendRecordBatch(qsubKindPacketFrame, messages[:count])
			for i, raw := range messages[:count] {
				if err == nil {
					switch {
					case raw[0] == dataMessage:
						l.tx.Add(uint64(len(raw) - 1))
					case raw[0] == ipMessage:
						l.tx.Add(uint64(len(raw) - 2 + packet.HeaderSize))
					}
				}
				messages[i] = nil
				owners[i].Release()
				owners[i] = nil
			}
			if err != nil {
				l.stop()
				return
			}
			if !more {
				break
			}
		}
	}
}

func (l *Link) packetReadLoop(sub Substream) {
	defer l.wg.Done()
	var ready [packetbuf.BatchSize]*packetbuf.Buffer
	count := 0
	flush := func() {
		if count == 0 {
			return
		}
		l.dropped.Add(uint64(l.ownedPackets.Put(ready[:count])))
		clear(ready[:count])
		count = 0
	}
	defer func() {
		packetbuf.ReleaseAll(ready[:count])
	}()
	for {
		kind, body, owner, err := sub.ReceiveOwnedRecord()
		if err != nil {
			owner.Release()
			flush()
			if l.ctx.Err() == nil {
				l.stop()
			}
			return
		}
		if kind != qsubKindPacketFrame || len(body) == 0 {
			owner.Release()
			flush()
			l.stop()
			return
		}
		switch body[0] {
		case dataMessage:
			if len(body) <= packet.HeaderSize+1 || len(body) > packet.MaxFrame+1 || body[1+6] == packet.KindIP {
				owner.Release()
				flush()
				l.stop()
				return
			}
			l.rx.Add(uint64(len(body) - 1))
			// owner.Data holds [kind (1B)][dataMessage (1B)][overlay frame...].
			owner.Advance(2)
			ready[count] = owner
			count++
		case ipMessage:
			if len(body) <= 2 || len(body)-2 > packet.MaxPayload {
				owner.Release()
				flush()
				l.stop()
				return
			}
			buffer := packetbuf.Get(packet.HeaderSize + len(body) - 2)
			if !l.headers.Rebuild(buffer.Data[:packet.HeaderSize], l.networkWire, body[1], body[2:]) {
				buffer.Release()
				owner.Release()
				l.dropped.Add(1)
				continue
			}
			copy(buffer.Data[packet.HeaderSize:], body[2:])
			owner.Release()
			l.rx.Add(uint64(len(buffer.Data)))
			ready[count] = buffer
			count++
		default:
			owner.Release()
			flush()
			l.stop()
			return
		}
		if count == len(ready) {
			flush()
		} else {
			// Flush promptly when no buffered data waits on the stream reader.
			flush()
		}
	}
}
