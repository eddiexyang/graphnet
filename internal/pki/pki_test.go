package pki

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"
	"time"
)

func TestRenewingCertificateReissuesBeforeExpiry(t *testing.T) {
	now := time.Now()
	leaf := func(notAfter time.Time) *tls.Certificate {
		return &tls.Certificate{Leaf: &x509.Certificate{NotAfter: notAfter}}
	}
	fresh := leaf(now.AddDate(1, 0, 0))
	issued := 0
	var failure error
	r := &renewingCertificate{issue: func() (*tls.Certificate, error) { issued++; return fresh, failure }}

	r.cert = leaf(now.Add(RenewBefore + time.Hour))
	if got, err := r.get(now); err != nil || got != r.cert || issued != 0 {
		t.Fatalf("renewed a certificate outside the window: issued=%d err=%v", issued, err)
	}
	r.cert = leaf(now.Add(RenewBefore - time.Hour))
	if got, err := r.get(now); err != nil || got != fresh || issued != 1 {
		t.Fatalf("certificate in the window not renewed: issued=%d err=%v", issued, err)
	}

	failure = errors.New("signing failed")
	due := leaf(now.Add(time.Hour))
	r.cert = due
	if got, err := r.get(now); err != nil || got != due {
		t.Fatalf("a failed renewal dropped a still valid certificate: %v", err)
	}
	r.cert = leaf(now.Add(-time.Hour))
	if _, err := r.get(now); err == nil {
		t.Fatal("served an expired certificate after a failed renewal")
	}
}

func TestNeedsRenewal(t *testing.T) {
	now := time.Now()
	for _, c := range []struct {
		left time.Duration
		want bool
	}{{-time.Hour, true}, {time.Hour, true}, {RenewBefore, true}, {RenewBefore + time.Minute, false}} {
		if got := NeedsRenewal(&x509.Certificate{NotAfter: now.Add(c.left)}, now); got != c.want {
			t.Errorf("left %s: %t, want %t", c.left, got, c.want)
		}
	}
	if !NeedsRenewal(nil, now) {
		t.Error("missing certificate not renewed")
	}
}
