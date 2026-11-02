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

	"github.com/Armur-Ai/Engira/pkg/intel"
	contracts "github.com/Armur-Ai/armur-contracts"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: engira enrich < inventory.json   |   engira score <cvss-vector>   |   engira version")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "enrich":
		runEnrich()
	case "score":
		runScore(os.Args[2:])
	case "version":
		fmt.Printf("engira (scaffold) — contracts %s\n", contracts.SchemaVersion)
	default:
		fmt.Fprintln(os.Stderr, "unknown command")
		os.Exit(2)
	}
}

func runScore(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: engira score 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'")
		os.Exit(2)
	}
	s, err := intel.CVSSv31BaseScore(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "score: %v\n", err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(s)
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
