package link

import (
	"context"
	"errors"
	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/packet"
	"github.com/eddiexyang/graphnet/internal/packetbuf"
	"testing"
)

func TestTCPBacklogOwnershipAndDrain(t *testing.T) {
	for _, kind := range []model.Transport{model.TCP, model.QUIC, model.UDP} {
		t.Run(string(kind), func(t *testing.T) {
			l := &Link{ctx: context.Background(), info: Info{Transport: kind}, dataReady: make(chan struct{}, 1)}
			l.dataGeneration.Store(1)
			// Exceptional unpooled owners make release observable without pool reuse.
			owners := make([]*packetbuf.Buffer, 128)
			for i := range owners {
				owners[i] = packetbuf.Wrap(make([]byte, 4096))
			}
			err := l.SendOwnedBatch(context.Background(), owners)
			// Each zero frame is an IP packet, queued as an IP message.
			size := 4096 - packet.HeaderSize + 2
			want := 128
			if l.tcpBacked() {
				want = tcpQueueBytes / size
				if !errors.Is(err, ErrQueueFull) {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if l.dataCount != want || l.dataBytes != want*size {
				t.Fatalf("count=%d bytes=%d", l.dataCount, l.dataBytes)
			}
			// Queued IP messages keep their owners' storage; the rest are released.
			for i, b := range owners {
				if i < want && l.data[i].buffer != b || i >= want && b.Data != nil {
					t.Fatalf("owner %d neither queued in place nor released", i)
				}
			}
			for l.dataCount > 0 {
				l.takeData().buffer.Release()
			}
			if l.dataBytes != 0 {
				t.Fatal("drain leaked byte budget")
			}
			if err := l.Send(context.Background(), make([]byte, 4096)); err != nil {
				t.Fatal(err)
			}
			l.takeData().buffer.Release()
			if l.dataBytes != 0 {
				t.Fatal("refill leaked budget")
			}
		})
	}
}
