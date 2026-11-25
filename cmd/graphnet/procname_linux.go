package main

import (
	"os"
	"path/filepath"
)

// Rename every thread: threads the runtime starts later copy the name of the
// thread that creates them, and ps and btop show the main thread's.
func init() {
	name := processName(os.Args[1:])
	if name == "" {
		return
	}
	tasks, _ := filepath.Glob("/proc/self/task/*/comm")
	for _, comm := range tasks {
		_ = os.WriteFile(comm, []byte(name), 0)
	}
}
