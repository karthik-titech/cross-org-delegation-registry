package main

import (
	"flag"
	"fmt"
	"os"

	"example.org/pedigree/reference/pedigree"
)

func main() {
	dir := flag.String("dir", pedigree.DefaultVectorDir(), "directory containing PEDIGREE vectors and expected.json")
	flag.Parse()
	if err := pedigree.RunVectors(*dir, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
