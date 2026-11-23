package cluster

import (
	"errors"
	"net"
	"reflect"
	"time"

	"github.com/eddiexyang/graphnet/internal/discovery"
	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/store"
)

func (r *Runtime) PublishEndpoints(endpoints []model.ServerEndpoint) error {
	for range 8 {
		state, err := r.DB.Read()
		if err != nil {
			return err
		}
		_, err = r.DB.Update(state.Revision, func(state *model.State) error {
			for i := range state.Servers {
				p := &state.Servers[i]
				if p.ID != r.Identity.ID {
					continue
				}
				combined := []model.ServerEndpoint{}
				urls := map[string]bool{}
				for _, e := range p.Endpoints {
					if e.Source == model.Manual {
						combined = append(combined, e)
						urls[e.URL] = true
					}
				}
				for _, e := range endpoints {
					if !urls[e.URL] && len(combined) < model.MaxEndpoints {
						for _, prior := range p.Endpoints {
							candidate := e
							candidate.ExpiresAt = prior.ExpiresAt
							if e.Source == model.Observed && candidate == prior {
								e.ExpiresAt = discovery.PublishedExpiry(prior.ExpiresAt, e.ExpiresAt, time.Now())
								break
							}
						}
						combined = append(combined, e)
						urls[e.URL] = true
					}
				}
				if reflect.DeepEqual(combined, p.Endpoints) {
					return errEndpointsUnchanged
				}
				p.Endpoints = combined
				return nil
			}
			return errors.New("server absent from cluster")
		})
		if errors.Is(err, errEndpointsUnchanged) {
			return nil
		}
		if errors.Is(err, store.ErrConflict) {
			continue
		}
		return err
	}
	return store.ErrConflict
}

var errEndpointsUnchanged = errors.New("endpoints unchanged")

func ValidateServerSTUN(servers []string) error {
	if err := model.ValidateSTUNServers(servers); err != nil {
		return err
	}
	for _, s := range servers {
		kind, address, err := model.ParseSTUNServer(s)
		if err != nil {
			return err
		}
		_, port, err := net.SplitHostPort(address)
		if err != nil || port == "" {
			return errors.New("server discovery requires host:port")
		}
		if kind != model.TCP {
			return errors.New("server discovery requires TCP STUN")
		}
	}
	return nil
}
