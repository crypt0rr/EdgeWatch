// Command gen-api-types writes src/generated/api-types.ts, the TypeScript
// declarations of the API response structs that web.ResponseTypes lists.
// Run it from the repository root after changing one of those structs:
//
//	go run ./scripts/gen-api-types
//
// The file is committed source. CI runs the command and fails when the file
// it writes differs from the committed one.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/crypt0rr/edgewatch/internal/apitypes"
	"github.com/crypt0rr/edgewatch/internal/web"
)

// output is the generated file, relative to the repository root.
const output = "src/generated/api-types.ts"

func main() {
	os.Exit(run(os.Args[1:], web.ResponseTypes(), os.Stderr))
}

// run writes the declarations of the types and returns the exit status: 2
// for invalid arguments and 1 when the declarations cannot be generated or
// written.
func run(args []string, types []apitypes.Type, stderr io.Writer) int {
	flags := flag.NewFlagSet("gen-api-types", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("o", output, "the file to write")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "gen-api-types takes no arguments, got %q\n", flags.Args())
		return 2
	}
	content, err := apitypes.Generate(types)
	if err != nil {
		fmt.Fprintln(stderr, "gen-api-types:", err)
		return 1
	}
	// The directory is committed, so a missing one means that the command
	// runs outside the repository root; it is not created there.
	if err := os.WriteFile(*path, content, 0o644); err != nil {
		fmt.Fprintf(stderr, "gen-api-types: %v; run it from the repository root\n", err)
		return 1
	}
	return 0
}
