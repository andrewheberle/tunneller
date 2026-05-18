package main

import (
	"context"
	"fmt"
	"os"

	"github.com/andrewheberle/tunneller/internal/pkg/cmd"
)

func main() {
	// run main command
	if err := cmd.Execute(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "\nError: %s\n", err)
		os.Exit(1)
	}
}
