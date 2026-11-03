// Command engira is the standalone intelligence/reporting CLI. `enrich` reads a
// contracts.DependencyInventory (JSON on stdin) and emits a
// contracts.IntelligenceResult envelope.
//
// enrich matches a dependency inventory against the bundled example advisory set
// and emits an IntelligenceResult envelope (or, with --report, a Markdown
// report). The matching logic + CVSS calculator are real; the bundled advisory
// data is a small illustrative set (a complete, current feed is commercial).
package main

import (
	"context"
	"encoding/json"
	"flag"
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
		runEnrich(os.Args[2:])
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

func runEnrich(args []string) {
	fs := flag.NewFlagSet("enrich", flag.ExitOnError)
	report := fs.Bool("report", false, "render a Markdown report instead of the JSON envelope")
	_ = fs.Parse(args)

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
	// Use the real advisory matcher over the bundled example set.
	e := intel.New(intel.NewListMatcher("example-advisories", intel.ExampleAdvisories()))
	res, err := e.Enrich(context.Background(), inv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "enrich: %v\n", err)
		os.Exit(1)
	}

	if *report {
		fmt.Print(intel.RenderMarkdown(res))
		return
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
