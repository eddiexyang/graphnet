package client

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const (
	rawIPNATTTL        = 60 * time.Second
	rawIPNATMaxEntries = 2048
)

type rawICMPKey struct {
	ipv6 bool
	id   uint16
	seq  uint16
}

type rawProtoKey struct {
	proto  uint8
	remote netip.Addr
}

type rawNATEntry struct {
	clientSrc netip.Addr
	updated   time.Time
}

type rawIPRelay struct {
	handler atomic.Pointer[func([]byte)]

	mu        sync.Mutex
	icmpMap   map[rawICMPKey]rawNATEntry
	protoMap  map[rawProtoKey]rawNATEntry
	lastSrc4  rawNATEntry
	lastSrc6  rawNATEntry
	lastPrune time.Time
}

func newRawIPRelay() *rawIPRelay {
	return &rawIPRelay{
		icmpMap:  make(map[rawICMPKey]rawNATEntry),
		protoMap: make(map[rawProtoKey]rawNATEntry),
	}
}

func (r *rawIPRelay) setHandler(fn func([]byte)) {
	if fn == nil {
		r.handler.Store(nil)
		return
	}
	r.handler.Store(&fn)
}

func (r *rawIPRelay) recordOutbound(pkt []byte, clientSrc, dst netip.Addr) {
	proto, upperOff, ok := ipUpperInfo(pkt)
	if !ok {
		return
	}
	now := time.Now()
	entry := rawNATEntry{clientSrc: clientSrc, updated: now}
	r.mu.Lock()
	defer r.mu.Unlock()
	if now.Sub(r.lastPrune) > 15*time.Second || len(r.icmpMap) >= rawIPNATMaxEntries || len(r.protoMap) >= rawIPNATMaxEntries {
		r.pruneLocked(now)
	}
	if clientSrc.Is4() {
		r.lastSrc4 = entry
	} else {
		r.lastSrc6 = entry
	}
	if !clientSrc.Is6() && proto == 1 && len(pkt) >= upperOff+8 && pkt[upperOff] == 8 {
		key := rawICMPKey{
			ipv6: false,
			id:   binary.BigEndian.Uint16(pkt[upperOff+4 : upperOff+6]),
			seq:  binary.BigEndian.Uint16(pkt[upperOff+6 : upperOff+8]),
		}
		r.icmpMap[key] = entry
		return
	}
	if clientSrc.Is6() && proto == 58 && len(pkt) >= upperOff+8 && pkt[upperOff] == 128 {
		key := rawICMPKey{
			ipv6: true,
			id:   binary.BigEndian.Uint16(pkt[upperOff+4 : upperOff+6]),
			seq:  binary.BigEndian.Uint16(pkt[upperOff+6 : upperOff+8]),
		}
		r.icmpMap[key] = entry
		return
	}
	r.protoMap[rawProtoKey{proto: proto, remote: dst}] = entry
}

func (r *rawIPRelay) pruneLocked(now time.Time) {
	r.lastPrune = now
	for k, v := range r.icmpMap {
		if now.Sub(v.updated) > rawIPNATTTL {
			delete(r.icmpMap, k)
		}
	}
	for k, v := range r.protoMap {
		if now.Sub(v.updated) > rawIPNATTTL {
			delete(r.protoMap, k)
		}
	}
	for len(r.icmpMap) >= rawIPNATMaxEntries {
		for k := range r.icmpMap {
			delete(r.icmpMap, k)
			break
		}
	}
	for len(r.protoMap) >= rawIPNATMaxEntries {
		for k := range r.protoMap {
			delete(r.protoMap, k)
			break
		}
	}
}

func (r *rawIPRelay) lookupInbound(pkt []byte, local netip.Addr) (netip.Addr, bool) {
	proto, upperOff, ok := ipUpperInfo(pkt)
	if !ok {
		return netip.Addr{}, false
	}
	is6 := pkt[0]>>4 == 6
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()

	if !is6 && proto == 1 && len(pkt) >= upperOff+8 {
		icmpType := pkt[upperOff]
		if icmpType == 0 { // Echo Reply
			key := rawICMPKey{
				ipv6: false,
				id:   binary.BigEndian.Uint16(pkt[upperOff+4 : upperOff+6]),
				seq:  binary.BigEndian.Uint16(pkt[upperOff+6 : upperOff+8]),
			}
			if e, found := r.icmpMap[key]; found && now.Sub(e.updated) <= rawIPNATTTL {
				return e.clientSrc, true
			}
		} else if isICMPv4Error(icmpType) {
			if src, found := r.lookupQuotedV4Locked(pkt[upperOff+8:], now); found {
				return src, true
			}
		}
	}
	if is6 && proto == 58 && len(pkt) >= upperOff+8 {
		icmpType := pkt[upperOff]
		if icmpType == 129 { // Echo Reply
			key := rawICMPKey{
				ipv6: true,
				id:   binary.BigEndian.Uint16(pkt[upperOff+4 : upperOff+6]),
				seq:  binary.BigEndian.Uint16(pkt[upperOff+6 : upperOff+8]),
			}
			if e, found := r.icmpMap[key]; found && now.Sub(e.updated) <= rawIPNATTTL {
				return e.clientSrc, true
			}
		} else if isICMPv6Error(icmpType) {
			if src, found := r.lookupQuotedV6Locked(pkt[upperOff+8:], now); found {
				return src, true
			}
		}
	}
	if srcIP, _, ok := ipAddresses(pkt); ok {
		if e, found := r.protoMap[rawProtoKey{proto: proto, remote: srcIP}]; found && now.Sub(e.updated) <= rawIPNATTTL {
			return e.clientSrc, true
		}
	}
	if !is6 && r.lastSrc4.clientSrc.Is4() && now.Sub(r.lastSrc4.updated) <= rawIPNATTTL {
		return r.lastSrc4.clientSrc, true
	}
	if is6 && r.lastSrc6.clientSrc.Is6() && now.Sub(r.lastSrc6.updated) <= rawIPNATTTL {
		return r.lastSrc6.clientSrc, true
	}
	return netip.Addr{}, false
}

func (r *rawIPRelay) lookupQuotedV4Locked(inner []byte, now time.Time) (netip.Addr, bool) {
	if len(inner) < 20 || inner[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	ihl := int(inner[0]&0x0f) * 4
	if ihl < 20 || len(inner) < ihl {
		return netip.Addr{}, false
	}
	proto := inner[9]
	dst := netip.AddrFrom4([4]byte(inner[16:20]))
	if proto == 1 && len(inner) >= ihl+8 && inner[ihl] == 8 {
		key := rawICMPKey{
			ipv6: false,
			id:   binary.BigEndian.Uint16(inner[ihl+4 : ihl+6]),
			seq:  binary.BigEndian.Uint16(inner[ihl+6 : ihl+8]),
		}
		if e, found := r.icmpMap[key]; found && now.Sub(e.updated) <= rawIPNATTTL {
			return e.clientSrc, true
		}
	}
	if e, found := r.protoMap[rawProtoKey{proto: proto, remote: dst}]; found && now.Sub(e.updated) <= rawIPNATTTL {
		return e.clientSrc, true
	}
	return netip.Addr{}, false
}

func (r *rawIPRelay) lookupQuotedV6Locked(inner []byte, now time.Time) (netip.Addr, bool) {
	if len(inner) < 40 || inner[0]>>4 != 6 {
		return netip.Addr{}, false
	}
	proto, upperOff, ok := ipUpperInfo(inner)
	if !ok {
		return netip.Addr{}, false
	}
	dst := netip.AddrFrom16([16]byte(inner[24:40]))
	if proto == 58 && len(inner) >= upperOff+8 && inner[upperOff] == 128 {
		key := rawICMPKey{
			ipv6: true,
			id:   binary.BigEndian.Uint16(inner[upperOff+4 : upperOff+6]),
			seq:  binary.BigEndian.Uint16(inner[upperOff+6 : upperOff+8]),
		}
		if e, found := r.icmpMap[key]; found && now.Sub(e.updated) <= rawIPNATTTL {
			return e.clientSrc, true
		}
	}
	if e, found := r.protoMap[rawProtoKey{proto: proto, remote: dst}]; found && now.Sub(e.updated) <= rawIPNATTTL {
		return e.clientSrc, true
	}
	return netip.Addr{}, false
}

func (r *rawIPRelay) deliver(local netip.Addr, raw []byte) bool {
	fnPtr := r.handler.Load()
	if fnPtr == nil {
		return false
	}
	clientSrc, ok := r.lookupInbound(raw, local)
	if !ok {
		return false
	}
	out := append([]byte(nil), raw...)
	if !rewriteInboundPacket(out, local, clientSrc) {
		return false
	}
	(*fnPtr)(out)
	return true
}

// SetIPHandler registers a callback that receives inbound non-TCP/non-UDP raw
// IPv4/IPv6 packets (such as ICMP replies, ICMP Time Exceeded, GRE, ESP, etc.)
// with their destination address restored to the original caller source IP.
func (c *Client) SetIPHandler(handler func(packet []byte)) {
	c.rawIP.setHandler(handler)
}

// WriteIP forwards a raw L3 IPv4/IPv6 packet through the GraphNet network that
// routes its destination. The packet's source IP is rewritten to this client
// node's overlay address and restored on matching replies passed to SetIPHandler.
func (c *Client) WriteIP(ctx context.Context, raw []byte) error {
	src, dst, ok := ipAddresses(raw)
	if !ok {
		return errors.New("graphnet: invalid IP packet")
	}
	network, n, err := c.route(ctx, dst)
	if err != nil {
		return err
	}
	local := n.address()
	if local.Is4() != dst.Is4() || local.Is4() != src.Is4() {
		return fmt.Errorf("%w: %s is not in the network's address family", ErrUnreachable, dst)
	}
	pkt := append([]byte(nil), raw...)
	if !rewriteOutboundPacket(pkt, src, local) {
		return errors.New("graphnet: malformed IP packet")
	}
	c.rawIP.recordOutbound(pkt, src, dst)
	return c.runtime.SendIP(ctx, network, pkt)
}

func ipUpperProtocol(p []byte) (uint8, bool) {
	proto, _, ok := ipUpperInfo(p)
	return proto, ok
}

func ipUpperInfo(p []byte) (proto uint8, upperOff int, ok bool) {
	if len(p) < 1 {
		return 0, 0, false
	}
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 {
			return 0, 0, false
		}
		ihl := int(p[0]&0x0f) * 4
		if ihl < 20 || len(p) < ihl {
			return 0, 0, false
		}
		return p[9], ihl, true
	case 6:
		if len(p) < 40 {
			return 0, 0, false
		}
		next := p[6]
		off := 40
		for range 8 {
			switch next {
			case 0, 43, 60: // Hop-by-Hop, Routing, Destination Options
				if len(p) < off+2 {
					return 0, 0, false
				}
				extLen := (int(p[off+1]) + 1) * 8
				if len(p) < off+extLen {
					return 0, 0, false
				}
				next = p[off]
				off += extLen
			case 44: // Fragment header (8 bytes)
				if len(p) < off+8 {
					return 0, 0, false
				}
				next = p[off]
				fragOff := binary.BigEndian.Uint16(p[off+2:off+4]) & 0xfff8
				off += 8
				if fragOff != 0 {
					return next, off, true
				}
			default:
				return next, off, true
			}
		}
		return next, off, true
	default:
		return 0, 0, false
	}
}

func ipAddresses(p []byte) (src, dst netip.Addr, ok bool) {
	if len(p) < 1 {
		return netip.Addr{}, netip.Addr{}, false
	}
	switch p[0] >> 4 {
	case 4:
		if len(p) < 20 {
			return netip.Addr{}, netip.Addr{}, false
		}
		ihl := int(p[0]&0x0f) * 4
		if ihl < 20 || len(p) < ihl {
			return netip.Addr{}, netip.Addr{}, false
		}
		return netip.AddrFrom4([4]byte(p[12:16])), netip.AddrFrom4([4]byte(p[16:20])), true
	case 6:
		if len(p) < 40 {
			return netip.Addr{}, netip.Addr{}, false
		}
		return netip.AddrFrom16([16]byte(p[8:24])), netip.AddrFrom16([16]byte(p[24:40])), true
	default:
		return netip.Addr{}, netip.Addr{}, false
	}
}

func isICMPv4Error(t uint8) bool {
	return t == 3 || t == 4 || t == 5 || t == 11 || t == 12
}

func isICMPv6Error(t uint8) bool {
	return t == 1 || t == 2 || t == 3 || t == 4
}

func rewriteOutboundPacket(pkt []byte, oldSrc, newSrc netip.Addr) bool {
	if oldSrc == newSrc {
		return true
	}
	switch pkt[0] >> 4 {
	case 4:
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl {
			return false
		}
		copy(pkt[12:16], newSrc.AsSlice())
		pkt[10], pkt[11] = 0, 0
		binary.BigEndian.PutUint16(pkt[10:12], rawInternetChecksum(pkt[:ihl]))
		return true
	case 6:
		if len(pkt) < 40 {
			return false
		}
		proto, upperOff, ok := ipUpperInfo(pkt)
		if !ok {
			return false
		}
		copy(pkt[8:24], newSrc.AsSlice())
		if proto == 58 && len(pkt) >= upperOff+4 {
			pkt[upperOff+2], pkt[upperOff+3] = 0, 0
			binary.BigEndian.PutUint16(pkt[upperOff+2:upperOff+4], icmpv6Checksum(pkt[8:24], pkt[24:40], pkt[upperOff:]))
		}
		return true
	default:
		return false
	}
}

func rewriteInboundPacket(pkt []byte, local, clientSrc netip.Addr) bool {
	if local == clientSrc {
		return true
	}
	switch pkt[0] >> 4 {
	case 4:
		ihl := int(pkt[0]&0x0f) * 4
		if ihl < 20 || len(pkt) < ihl {
			return false
		}
		copy(pkt[16:20], clientSrc.AsSlice())
		pkt[10], pkt[11] = 0, 0
		binary.BigEndian.PutUint16(pkt[10:12], rawInternetChecksum(pkt[:ihl]))
		if pkt[9] == 1 && len(pkt) >= ihl+8 && isICMPv4Error(pkt[ihl]) {
			inner := pkt[ihl+8:]
			if len(inner) >= 20 && inner[0]>>4 == 4 {
				innerIHL := int(inner[0]&0x0f) * 4
				if innerIHL >= 20 && len(inner) >= innerIHL && netip.AddrFrom4([4]byte(inner[12:16])) == local {
					copy(inner[12:16], clientSrc.AsSlice())
					inner[10], inner[11] = 0, 0
					binary.BigEndian.PutUint16(inner[10:12], rawInternetChecksum(inner[:innerIHL]))
					pkt[ihl+2], pkt[ihl+3] = 0, 0
					binary.BigEndian.PutUint16(pkt[ihl+2:ihl+4], rawInternetChecksum(pkt[ihl:]))
				}
			}
		}
		return true
	case 6:
		if len(pkt) < 40 {
			return false
		}
		proto, upperOff, ok := ipUpperInfo(pkt)
		if !ok {
			return false
		}
		copy(pkt[24:40], clientSrc.AsSlice())
		if proto == 58 && len(pkt) >= upperOff+8 {
			if isICMPv6Error(pkt[upperOff]) {
				inner := pkt[upperOff+8:]
				if len(inner) >= 40 && inner[0]>>4 == 6 && netip.AddrFrom16([16]byte(inner[8:24])) == local {
					copy(inner[8:24], clientSrc.AsSlice())
					if innerProto, innerOff, innerOK := ipUpperInfo(inner); innerOK && innerProto == 58 && len(inner) >= innerOff+4 {
						oldCsum := binary.BigEndian.Uint16(inner[innerOff+2 : innerOff+4])
						newCsum := checksumAdjustBytes(oldCsum, local.AsSlice(), clientSrc.AsSlice())
						binary.BigEndian.PutUint16(inner[innerOff+2:innerOff+4], newCsum)
					}
				}
			}
			pkt[upperOff+2], pkt[upperOff+3] = 0, 0
			binary.BigEndian.PutUint16(pkt[upperOff+2:upperOff+4], icmpv6Checksum(pkt[8:24], pkt[24:40], pkt[upperOff:]))
		}
		return true
	default:
		return false
	}
}

func rawInternetChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) != 0 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func icmpv6Checksum(src, dst, payload []byte) uint16 {
	var sum uint32
	add := func(b []byte) {
		for len(b) >= 2 {
			sum += uint32(binary.BigEndian.Uint16(b[:2]))
			b = b[2:]
		}
		if len(b) != 0 {
			sum += uint32(b[0]) << 8
		}
	}
	add(src)
	add(dst)
	var pseudo [8]byte
	binary.BigEndian.PutUint32(pseudo[0:4], uint32(len(payload)))
	pseudo[7] = 58
	add(pseudo[:])
	add(payload)
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// checksumAdjustBytes applies RFC 1624 incremental checksum adjustment when
// replacing even-length oldBytes with newBytes inside the covered data.
func checksumAdjustBytes(csum uint16, oldBytes, newBytes []byte) uint16 {
	sum := uint32(^csum)
	for i := 0; i+1 < len(oldBytes) && i+1 < len(newBytes); i += 2 {
		oldVal := uint32(binary.BigEndian.Uint16(oldBytes[i : i+2]))
		newVal := uint32(binary.BigEndian.Uint16(newBytes[i : i+2]))
		sum += (^oldVal) & 0xffff
		sum += newVal
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
