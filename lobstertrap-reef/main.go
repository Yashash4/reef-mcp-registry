package main

import (
	"fmt"
	"os"

	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
