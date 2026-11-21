package main

import (
	"flag"
	"fmt"
	"os"

	"example.org/pedigree/reference/pedigree"
)

func main() {
	dir := flag.String("out", pedigree.DefaultVectorDir(), "directory for generated PEDIGREE vectors")
	flag.Parse()
	if err := pedigree.GenerateVectors(*dir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
