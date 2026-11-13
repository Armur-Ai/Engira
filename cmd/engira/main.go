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
		fmt.Fprintln(os.Stderr, "usage: engira enrich < inventory.json   |   engira triage < snapshot.json   |   engira diff <base.json> <head.json>   |   engira score <cvss-vector>   |   engira version")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "enrich":
		runEnrich(os.Args[2:])
	case "triage":
		runTriage(os.Args[2:])
	case "diff":
		runDiff(os.Args[2:])
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

// runTriage consumes a Pentest Swarm AssessmentSnapshot envelope (JSON on
// stdin) and emits Engira's prioritized triage — JSON by default, or a Markdown
// report with --report.
func runTriage(args []string) {
	fs := flag.NewFlagSet("triage", flag.ExitOnError)
	report := fs.Bool("report", false, "render a Markdown report instead of the JSON envelope")
	_ = fs.Parse(args)

	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read stdin: %v\n", err)
		os.Exit(1)
	}
	var env contracts.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		fmt.Fprintf(os.Stderr, "parse envelope: %v\n", err)
		os.Exit(1)
	}
	if _, err := contracts.CheckEnvelope(env); err != nil {
		fmt.Fprintf(os.Stderr, "triage: incompatible envelope: %v\n", err)
		os.Exit(1)
	}
	if env.Kind != "AssessmentSnapshot" {
		fmt.Fprintf(os.Stderr, "triage: expected an AssessmentSnapshot envelope, got %q\n", env.Kind)
		os.Exit(1)
	}
	var snap contracts.AssessmentSnapshot
	if err := env.Decode(&snap); err != nil {
		fmt.Fprintf(os.Stderr, "decode snapshot: %v\n", err)
		os.Exit(1)
	}
	if err := snap.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "triage: %v\n", err)
		os.Exit(1)
	}
	summary := intel.TriageSnapshot(snap)

	if *report {
		fmt.Print(intel.RenderTriageMarkdown(summary))
		return
	}
	out, err := contracts.NewEnvelope(
		contracts.NSEngira,
		contracts.Producer{Product: "engira", Version: "scaffold"},
		"TriageSummary", summary,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "envelope: %v\n", err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

// loadSnapshot reads an AssessmentSnapshot envelope from a file and returns the
// decoded snapshot, rejecting an envelope whose schema major Engira can't read.
func loadSnapshot(path string) (contracts.AssessmentSnapshot, error) {
	var snap contracts.AssessmentSnapshot
	raw, err := os.ReadFile(path)
	if err != nil {
		return snap, fmt.Errorf("read %s: %w", path, err)
	}
	var env contracts.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return snap, fmt.Errorf("parse envelope %s: %w", path, err)
	}
	if _, err := contracts.CheckEnvelope(env); err != nil {
		return snap, fmt.Errorf("incompatible envelope %s: %w", path, err)
	}
	if env.Kind != "AssessmentSnapshot" {
		return snap, fmt.Errorf("%s: expected an AssessmentSnapshot envelope, got %q", path, env.Kind)
	}
	if err := env.Decode(&snap); err != nil {
		return snap, fmt.Errorf("decode snapshot %s: %w", path, err)
	}
	if err := snap.Validate(); err != nil {
		return snap, fmt.Errorf("%s: %w", path, err)
	}
	return snap, nil
}

// runDiff compares a baseline AssessmentSnapshot against a later one and reports
// how the posture moved — new/fixed/persisting transitions and (the key signal)
// which went from modeled to proven. JSON envelope by default, or Markdown with
// --report.
func runDiff(args []string) {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	report := fs.Bool("report", false, "render a Markdown report instead of the JSON envelope")
	_ = fs.Parse(args)
	if fs.NArg() != 2 {
		fmt.Fprintln(os.Stderr, "usage: engira diff [--report] <baseline-snapshot.json> <head-snapshot.json>")
		os.Exit(2)
	}
	base, err := loadSnapshot(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "diff: %v\n", err)
		os.Exit(1)
	}
	head, err := loadSnapshot(fs.Arg(1))
	if err != nil {
		fmt.Fprintf(os.Stderr, "diff: %v\n", err)
		os.Exit(1)
	}
	d := intel.DiffSnapshots(base, head)

	if *report {
		fmt.Print(intel.RenderDiffMarkdown(d))
		return
	}
	out, err := contracts.NewEnvelope(
		contracts.NSEngira,
		contracts.Producer{Product: "engira", Version: "scaffold"},
		"SnapshotDiff", d,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "envelope: %v\n", err)
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

func runEnrich(args []string) {
	fs := flag.NewFlagSet("enrich", flag.ExitOnError)
	report := fs.Bool("report", false, "render a Markdown report instead of the JSON envelope")
	advFile := fs.String("advisories", "", "path to a versioned advisory JSON file (default: bundled example set)")
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
	// Advisory source: a versioned file if given, else the bundled example set.
	snapshot, advisories := "example-advisories", intel.ExampleAdvisories()
	if *advFile != "" {
		snap, advs, err := intel.LoadAdvisories(*advFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "advisories: %v\n", err)
			os.Exit(1)
		}
		snapshot, advisories = snap, advs
	}
	e := intel.New(intel.NewListMatcher(snapshot, advisories))
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
