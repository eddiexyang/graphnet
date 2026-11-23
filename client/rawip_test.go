package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/eddiexyang/graphnet/internal/model"
)

func buildICMPv4Echo(src, dst netip.Addr, ttl uint8, id, seq uint16, payload []byte) []byte {
	pkt := make([]byte, 20+8+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = ttl
	pkt[9] = 1
	copy(pkt[12:16], src.AsSlice())
	copy(pkt[16:20], dst.AsSlice())
	pkt[20] = 8 // Echo Request
	binary.BigEndian.PutUint16(pkt[24:26], id)
	binary.BigEndian.PutUint16(pkt[26:28], seq)
	copy(pkt[28:], payload)
	binary.BigEndian.PutUint16(pkt[22:24], rawInternetChecksum(pkt[20:]))
	binary.BigEndian.PutUint16(pkt[10:12], rawInternetChecksum(pkt[:20]))
	return pkt
}

func buildGREv4(src, dst netip.Addr, ttl uint8, payload []byte) []byte {
	pkt := make([]byte, 20+4+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = ttl
	pkt[9] = 47 // GRE
	copy(pkt[12:16], src.AsSlice())
	copy(pkt[16:20], dst.AsSlice())
	binary.BigEndian.PutUint16(pkt[22:24], 0x0800)
	copy(pkt[24:], payload)
	binary.BigEndian.PutUint16(pkt[10:12], rawInternetChecksum(pkt[:20]))
	return pkt
}

func TestClientRawIPTracerouteEchoAndGRE(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 44
	clientKey := ed25519.NewKeyFromSeed(seed)
	cn := startClientNetwork(t, ctx, clientKey, clientKey.Public().(ed25519.PublicKey), model.TCP)

	// Make node 2 echo back ICMPv4 Echo Requests and GRE (proto 47) packets.
	netID := cn.state.Networks[0].ID
	node0Addr := cn.state.Networks[0].Nodes[0].Address
	node2Addr := cn.state.Networks[0].Nodes[2].Address
	cn.stacks[2].setRawIPHandler(func(raw []byte) bool {
		if len(raw) < 24 || raw[0]>>4 != 4 {
			return false
		}
		reply := append([]byte(nil), raw...)
		// Swap src and dst.
		copy(reply[12:16], raw[16:20])
		copy(reply[16:20], raw[12:16])
		reply[8] = 64
		if reply[9] == 1 && len(reply) >= 28 && reply[20] == 8 {
			reply[20] = 0 // Echo Reply
			reply[22], reply[23] = 0, 0
			binary.BigEndian.PutUint16(reply[22:24], rawInternetChecksum(reply[20:]))
		}
		reply[10], reply[11] = 0, 0
		binary.BigEndian.PutUint16(reply[10:12], rawInternetChecksum(reply[:20]))
		go func() { if err := cn.runtimes[2].SendIP(ctx, netID, reply); err != nil { t.Logf("node2 SendIP err: %v", err) } else { t.Logf("node2 sent reply proto=%d len=%d", reply[9], len(reply)) } }()
		return true
	})

	c, err := Start(ctx, Config{
		Server:     "https://controller.graphnet.test:" + cn.port,
		Lookup: func(context.Context, string, string) ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil },
		CA:         cn.ca.PEM,
		PrivateKey: clientKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	replies := make(chan []byte, 16)
	c.SetIPHandler(func(pkt []byte) {
		replies <- append([]byte(nil), pkt...)
	})

	tunSrc := netip.MustParseAddr("198.18.0.1")

	// Wait until client has route to node 2 (via node 0 -> node 1 -> node 2).
	// Routes and the end-to-end session come up after Start returns, and a
	// packet sent before then is dropped: resend until the echo is answered.
	probe := buildICMPv4Echo(tunSrc, node2Addr, 64, 0x1234, 1, []byte("ping-gn"))
	var echo []byte
	for echo == nil {
		err := c.WriteIP(ctx, probe)
		select {
		case echo = <-replies:
		case <-time.After(200 * time.Millisecond):
		case <-ctx.Done():
			t.Fatalf("WriteIP echo: no reply before deadline (last error: %v)", err)
		}
	}
	{
		if len(echo) < 28 || echo[0]>>4 != 4 || echo[9] != 1 || echo[20] != 0 {
			t.Fatalf("unexpected echo reply: %x", echo)
		}
		src, dst, _ := ipAddresses(echo)
		if src != node2Addr || dst != tunSrc {
			t.Fatalf("echo reply addrs = %s -> %s, want %s -> %s", src, dst, node2Addr, tunSrc)
		}
		if rawInternetChecksum(echo[:20]) != 0 || rawInternetChecksum(echo[20:]) != 0 {
			t.Fatalf("invalid echo reply checksums")
		}
		if binary.BigEndian.Uint16(echo[24:26]) != 0x1234 || binary.BigEndian.Uint16(echo[26:28]) != 1 {
			t.Fatalf("echo reply id/seq mismatch")
		}
	}

	// Resent echoes are each answered: drop their late replies first.
	for drained := false; !drained; {
		select {
		case <-replies:
		case <-time.After(300 * time.Millisecond):
			drained = true
		}
	}

	// TTL=1 probe must trigger ICMP Time Exceeded from first transit node (node 0)
	// with outer dst and inner quoted src both restored to tunSrc (198.18.0.1).
	var rep []byte
	for attempt := range uint16(5) {
		ttlProbe := buildICMPv4Echo(tunSrc, node2Addr, 1, 0x2222, 7+attempt, []byte("trace"))
		if err := c.WriteIP(ctx, ttlProbe); err != nil {
			t.Fatalf("WriteIP ttl=1: %v", err)
		}
		select {
		case rep = <-replies:
		case <-time.After(250 * time.Millisecond):
			continue
		}
		break
	}
	if rep == nil {
		t.Fatal("timed out waiting for ICMP Time Exceeded from transit node")
	}
	if true {
		if len(rep) < 20+8+20+8 || rep[0]>>4 != 4 || rep[9] != 1 || rep[20] != 11 {
			t.Fatalf("expected ICMPv4 Time Exceeded, got %x", rep)
		}
		src, dst, _ := ipAddresses(rep)
		if src != node0Addr || dst != tunSrc {
			t.Fatalf("time exceeded addrs = %s -> %s, want %s -> %s", src, dst, node0Addr, tunSrc)
		}
		if rawInternetChecksum(rep[:20]) != 0 || rawInternetChecksum(rep[20:]) != 0 {
			t.Fatalf("invalid outer IPv4/ICMP checksums")
		}
		inner := rep[28:]
		innerSrc, innerDst, _ := ipAddresses(inner)
		if innerSrc != tunSrc || innerDst != node2Addr {
			t.Fatalf("quoted inner addrs = %s -> %s, want %s -> %s", innerSrc, innerDst, tunSrc, node2Addr)
		}
		if rawInternetChecksum(inner[:20]) != 0 {
			t.Fatalf("invalid quoted inner IPv4 checksum")
		}
	}

	// Non-TCP/non-UDP arbitrary L3 protocol (GRE, proto 47) round-trip.
	grePayload := []byte("hello-l3-gre")
	gre := buildGREv4(tunSrc, node2Addr, 64, grePayload)
	if err := c.WriteIP(ctx, gre); err != nil {
		t.Fatalf("WriteIP GRE: %v", err)
	}
	select {
	case rep := <-replies:
		if len(rep) < 24 || rep[0]>>4 != 4 || rep[9] != 47 {
			t.Fatalf("expected GRE reply, got %x", rep)
		}
		src, dst, _ := ipAddresses(rep)
		if src != node2Addr || dst != tunSrc {
			t.Fatalf("GRE reply addrs = %s -> %s, want %s -> %s", src, dst, node2Addr, tunSrc)
		}
		if rawInternetChecksum(rep[:20]) != 0 {
			t.Fatalf("invalid GRE IPv4 header checksum")
		}
		if !bytes.Equal(rep[24:], grePayload) {
			t.Fatalf("GRE payload mismatch: got %q", rep[24:])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for GRE reply")
	}
}

func TestRawIPv6ICMPRewrite(t *testing.T) {
	clientSrc := netip.MustParseAddr("fdfe:dcba:9876::1")
	localOverlay := netip.MustParseAddr("fd00:666::12")
	hopAddr := netip.MustParseAddr("fd00:666::1")
	target := netip.MustParseAddr("2606:4700:4700::1111")

	// Build original IPv6 ICMPv6 Echo Request from clientSrc -> target.
	req := make([]byte, 40+12)
	req[0] = 0x60
	binary.BigEndian.PutUint16(req[4:6], 12)
	req[6] = 58
	req[7] = 1
	copy(req[8:24], clientSrc.AsSlice())
	copy(req[24:40], target.AsSlice())
	req[40] = 128 // Echo Request
	binary.BigEndian.PutUint16(req[44:46], 0xabcd)
	binary.BigEndian.PutUint16(req[46:48], 3)
	copy(req[48:], []byte("test"))
	origCsum := icmpv6Checksum(req[8:24], req[24:40], req[40:])
	binary.BigEndian.PutUint16(req[42:44], origCsum)

	// Outbound SNAT to localOverlay.
	out := append([]byte(nil), req...)
	if !rewriteOutboundPacket(out, clientSrc, localOverlay) {
		t.Fatal("rewriteOutboundPacket failed")
	}
	if icmpv6Checksum(out[8:24], out[24:40], out[40:]) != 0 {
		t.Fatal("invalid outbound ICMPv6 checksum after SNAT")
	}

	// Simulate transit router returning ICMPv6 Time Exceeded quoting out.
	te := make([]byte, 40+8+len(out))
	te[0] = 0x60
	binary.BigEndian.PutUint16(te[4:6], uint16(8+len(out)))
	te[6] = 58
	te[7] = 64
	copy(te[8:24], hopAddr.AsSlice())
	copy(te[24:40], localOverlay.AsSlice())
	te[40] = 3 // Time Exceeded
	copy(te[48:], out)
	binary.BigEndian.PutUint16(te[42:44], icmpv6Checksum(te[8:24], te[24:40], te[40:]))

	// Inbound reverse-NAT back to clientSrc.
	if !rewriteInboundPacket(te, localOverlay, clientSrc) {
		t.Fatal("rewriteInboundPacket failed")
	}
	if netip.AddrFrom16([16]byte(te[24:40])) != clientSrc {
		t.Fatal("outer IPv6 dst not restored")
	}
	if icmpv6Checksum(te[8:24], te[24:40], te[40:]) != 0 {
		t.Fatal("invalid outer ICMPv6 checksum after reverse-NAT")
	}
	quoted := te[48:]
	if netip.AddrFrom16([16]byte(quoted[8:24])) != clientSrc {
		t.Fatal("quoted inner IPv6 src not restored")
	}
	if binary.BigEndian.Uint16(quoted[42:44]) != origCsum {
		t.Fatalf("quoted inner ICMPv6 checksum = %04x, want %04x", binary.BigEndian.Uint16(quoted[42:44]), origCsum)
	}
}
