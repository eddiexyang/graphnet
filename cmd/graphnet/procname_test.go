package main

import (
	"strings"
	"testing"
)

func TestProcessName(t *testing.T) {
	for args, want := range map[string]string{
		"server":                         "graphnet-server",
		"server --listen=0.0.0.0:8443":   "graphnet-server",
		"server service install":         "",
		"agent":                          "graphnet-agent",
		"agent --data-dir /var/lib/x":    "graphnet-agent",
		"agent run":                      "graphnet-agent",
		"agent status --data-dir /var/x": "",
		"version":                        "",
		"":                               "",
	} {
		if got := processName(strings.Fields(args)); got != want {
			t.Errorf("%q: %q, want %q", args, got, want)
		}
	}
}
