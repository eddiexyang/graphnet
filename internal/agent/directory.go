package agent

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"errors"
	"time"

	"github.com/eddiexyang/graphnet/internal/model"
)

func validateDirectory(reg Registration, directory *model.ServerDirectory) error {
	if directory == nil {
		return nil
	}
	if err := directory.Validate(); err != nil {
		return err
	}
	if len(reg.CA) > 0 && !bytes.Equal(reg.CA, directory.CA) {
		return errors.New("controller directory changed trusted CA")
	}
	if reg.Directory != nil {
		if directory.ClusterID != reg.Directory.ClusterID || !bytes.Equal(directory.CA, reg.Directory.CA) {
			return errors.New("controller directory changed cluster identity")
		}
		if directory.Revision < reg.Directory.Revision {
			return errors.New("controller directory revision rollback")
		}
		if directory.Revision == reg.Directory.Revision {
			a, _ := json.Marshal(directory)
			b, _ := json.Marshal(reg.Directory)
			if !bytes.Equal(a, b) {
				return errors.New("controller directory revision changed content")
			}
		}
	}
	return nil
}
func (c *Cache) SaveDirectory(directory *model.ServerDirectory, roots *x509.CertPool) error {
	if directory == nil {
		return nil
	}
	c.mu.Lock()
	if c.reg == nil {
		c.mu.Unlock()
		return errors.New("missing registration")
	}
	reg := c.reg.clone()
	if err := validateDirectory(reg, directory); err != nil {
		c.mu.Unlock()
		return err
	}
	if len(reg.CA) == 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(directory.CA) {
			c.mu.Unlock()
			return errors.New("invalid directory CA")
		}
		cert, err := c.TLSCertificate(reg)
		if err != nil {
			c.mu.Unlock()
			return err
		}
		if _, err = cert.Leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			c.mu.Unlock()
			return err
		}
		if _, err = cert.Leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			c.mu.Unlock()
			return err
		}
	}
	reg.CA = bytes.Clone(directory.CA)
	reg.Directory = directory.Clone()
	c.reg = &reg
	c.mu.Unlock()
	if raw, err := json.Marshal(reg); err == nil {
		c.disk.put(reg.AgentID, keyRegistration, raw)
	}
	return nil
}

type controlTarget struct {
	key, origin, transport, tlsName string
	network                         bool // dialed through the network, not a host socket
}

func targets(reg Registration) []controlTarget {
	if reg.Directory == nil {
		return []controlTarget{{key: reg.Server, origin: reg.Server, transport: reg.Transport}}
	}
	out := []controlTarget{}
	for _, server := range reg.Directory.Servers {
		if server.Revoked {
			continue
		}
		for _, ep := range server.Endpoints {
			if ep.Source == model.Observed && time.Now().After(ep.ExpiresAt) {
				continue
			}
			out = append(out, controlTarget{key: string(server.ID) + "/" + ep.URL, origin: ep.Origin(), transport: ep.Transport, tlsName: server.TLSName()})
		}
	}
	return out
}

// targets combines an explicit runtime entrance with the cached directory.
// Address changes retain the existing CA and stable controller TLS identities;
// directory discovery and its validation continue to own persistent state.
func (c *Client) targets(reg Registration) []controlTarget {
	cached := targets(reg)
	if c.configuredServer == "" {
		return cached
	}
	kind := c.options.ServerTransport
	if kind == "" {
		kind = "tcp"
	}
	preferred := []controlTarget{}
	for _, target := range cached {
		transport := target.transport
		if transport == "" {
			transport = "tcp"
		}
		if target.origin == c.configuredServer && transport == kind {
			preferred = append(preferred, target)
		}
	}
	if len(preferred) == 0 {
		// A gateway entrance presents its own public certificate, not a Server identity.
		if reg.Directory == nil || kind == "https" {
			preferred = append(preferred, controlTarget{key: c.configuredServer, origin: c.configuredServer, transport: kind})
		} else {
			// The new entrance may belong to any admitted Server. Each attempt
			// still verifies that Server's existing TLS name; revoked identities
			// cannot be selected through an explicit address.
			for _, server := range reg.Directory.Servers {
				if !server.Revoked {
					preferred = append(preferred, controlTarget{
						key:    string(server.ID) + "/configured/" + kind + "/" + c.configuredServer,
						origin: c.configuredServer, transport: kind, tlsName: server.TLSName(),
					})
				}
			}
		}
	}
	seen := make(map[string]bool, len(preferred))
	for _, target := range preferred {
		seen[target.key] = true
	}
	configured := len(preferred)
	for _, target := range cached {
		if !seen[target.key] {
			preferred = append(preferred, target)
		}
	}
	// The configured address through the network comes last, offered only
	// after its direct dial failed while a configuration runs, whose routes
	// can carry it.
	if c.options.NetworkDial != nil && c.directDialFailed && c.reconcile.Configured() {
		for _, target := range preferred[:configured] {
			target.key += "#network"
			target.network = true
			preferred = append(preferred, target)
		}
	}
	return preferred
}

func (c *Cache) lastServer() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastSrv, nil
}
func (c *Cache) saveLastServer(key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastSrv = key
	return nil
}
