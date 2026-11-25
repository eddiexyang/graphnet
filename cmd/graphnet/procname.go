package main

import "strings"

// processName names the long-running commands, so the controller and an
// Agent on the same host tell apart in ps, top and btop. The kernel keeps
// at most 15 bytes of it.
func processName(args []string) string {
	if len(args) == 0 {
		return ""
	}
	sub := ""
	if len(args) > 1 {
		sub = args[1]
	}
	switch {
	case args[0] == "server" && (sub == "" || strings.HasPrefix(sub, "-")):
		return "graphnet-server"
	case args[0] == "agent" && (sub == "" || sub == "run" || strings.HasPrefix(sub, "-")):
		return "graphnet-agent"
	}
	return ""
}
