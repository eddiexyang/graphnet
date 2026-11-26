package forwarding_test

import (
	"context"

	"github.com/eddiexyang/graphnet/internal/forwarding"
	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/packetbuf"
)

// fromPeer hands r a copy of frame from peer, as a Link's owned batch does.
func fromPeer(r *forwarding.Router, ctx context.Context, peer model.ID, frame []byte) error {
	b := packetbuf.Get(len(frame))
	copy(b.Data, frame)
	return r.FromPeerOwnedBatch(ctx, peer, []*packetbuf.Buffer{b})
}
