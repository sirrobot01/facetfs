// facetfsd is the standalone FacetFS composition binary.
//
// Protocol serving is intentionally unavailable until the Phase 1 coordinator
// and the first frontend are implemented.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("facetfsd", flag.ContinueOnError)
	flags.SetOutput(stderr)
	showVersion := flags.Bool("version", false, "print version and exit")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Fprintf(stdout, "facetfsd %s\n", version)
		return nil
	}
	return fmt.Errorf("facetfsd: no serving profile is implemented yet; use -version to inspect the build")
}
