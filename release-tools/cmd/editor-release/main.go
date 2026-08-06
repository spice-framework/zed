package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/spice-framework/zed/release-tools/internal/release"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "editor-release:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		return fmt.Errorf("require package, sign, or verify command")
	}
	flags := flag.NewFlagSet(arguments[0], flag.ContinueOnError)
	root := flags.String("root", "..", "repository root")
	input := flags.String("input", "", "input artifact directory or file")
	output := flags.String("output", "", "new output directory")
	version := flags.String("version", "", "release version")
	commit := flags.String("commit", "", "release commit")
	epoch := flags.Int64("epoch", 0, "source date epoch")
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	options := release.Options{
		Root: *root, Input: *input, Output: *output,
		Version: *version, Commit: *commit, Epoch: *epoch,
	}
	switch arguments[0] {
	case "package":
		return release.Package(options)
	case "sign":
		return release.Sign(options)
	case "verify":
		result, err := release.Verify(options)
		if err == nil {
			fmt.Printf("%s %s verified: %d artifacts at %s\n", result.Repository, result.Version, result.Artifacts, result.Commit)
		}
		return err
	default:
		return fmt.Errorf("unknown command %q", arguments[0])
	}
}
