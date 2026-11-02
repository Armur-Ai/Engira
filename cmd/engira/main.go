// Command engira is the standalone intelligence/reporting CLI. `enrich` reads a
// contracts.DependencyInventory (JSON on stdin) and emits a
// contracts.IntelligenceResult envelope.
//
// Status: scaffold. The offline stub matcher resolves no advisories yet (the
// pinned dataset + CVSS calculator land in phase P3); the plumbing + envelope
// are real.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	contracts "github.com/Armur-Ai/armur-contracts"
	"github.com/Armur-Ai/Engira/pkg/intel"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: engira enrich < inventory.json   |   engira version")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "enrich":
		runEnrich()
	case "version":
		fmt.Printf("engira (scaffold) — contracts %s\n", contracts.SchemaVersion)
	default:
		fmt.Fprintln(os.Stderr, "unknown command")
		os.Exit(2)
	}
}

func runEnrich() {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read stdin: %v\n", err)
		os.Exit(1)
	}
	var inv contracts.DependencyInventory
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &inv); err != nil {
			fmt.Fprintf(os.Stderr, "parse inventory: %v\n", err)
			os.Exit(1)
		}
	}
	e := intel.New(intel.OfflineStubMatcher{})
	res, err := e.Enrich(context.Background(), inv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "enrich: %v\n", err)
		os.Exit(1)
	}
	env, err := contracts.NewEnvelope(
		contracts.NSEngira,
		contracts.Producer{Product: "engira", Version: "scaffold"},
		"IntelligenceResult", res,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "envelope: %v\n", err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(env)
}
