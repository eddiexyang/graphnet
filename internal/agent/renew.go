package agent

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/eddiexyang/graphnet/internal/model"
	"github.com/eddiexyang/graphnet/internal/pki"
)

// renewalClock is the time renewal decisions use; tests move it forward.
var renewalClock = time.Now

// renewCertificateIfDue renews an enrolled Agent's client certificate once it
// is within pki.RenewBefore of expiry, or has expired. It authenticates by a
// challenge signed with the Agent's key, which the controller accepts after the
// certificate has expired, and keeps the current certificate on failure. It
// reports whether the registration changed.
func (c *Client) renewCertificateIfDue(ctx context.Context) (bool, error) {
	reg, err := c.cache.Registration()
	if err != nil || reg == nil || reg.KeyOnly() {
		return false, err
	}
	cert, err := c.cache.TLSCertificate(*reg)
	if err != nil {
		return false, err
	}
	if !pki.NeedsRenewal(cert.Leaf, renewalClock()) {
		return false, nil
	}
	csr, err := c.cache.CSR()
	if err != nil {
		return false, err
	}
	body, err := json.Marshal(map[string]any{"csr": csr})
	if err != nil {
		return false, err
	}
	requestCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, "POST", c.server+model.AgentRenewPath, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	// Without a client certificate: an expired one fails the TLS handshake.
	transport := c.transport.Clone()
	if transport.TLSClientConfig != nil {
		transport.TLSClientConfig.Certificates = nil
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: &challengeSigner{base: transport, id: reg.AgentID, key: c.cache.PrivateKey()}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("renew agent certificate: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false, fmt.Errorf("renew agent certificate: HTTP %d", resp.StatusCode)
	}
	var result struct {
		AgentID     model.ID `json:"agent_id"`
		Certificate []byte   `json:"certificate"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxSnapshotBytes)).Decode(&result); err != nil {
		return false, err
	}
	if result.AgentID != reg.AgentID {
		return false, errors.New("renewed certificate names another agent")
	}
	next := reg.clone()
	next.Certificate = result.Certificate
	renewed, err := c.cache.TLSCertificate(next)
	if err != nil {
		return false, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(reg.CA) {
		return false, errors.New("registration has no valid controller CA")
	}
	if _, err := renewed.Leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return false, fmt.Errorf("verify renewed agent certificate: %w", err)
	}
	// Validity is recorded in whole seconds: an equal expiry is no rollback.
	if renewed.Leaf.NotAfter.Before(cert.Leaf.NotAfter) {
		return false, errors.New("renewed certificate expires before the current one")
	}
	if err := c.cache.SaveRegistration(next); err != nil {
		return false, err
	}
	c.options.Logger.Info("agent certificate renewed", "agent_id", reg.AgentID, "not_after", renewed.Leaf.NotAfter)
	return true, nil
}
