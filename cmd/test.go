package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Set when running cased-cli in test mode: cased-cli test <command> [command_args...]
var testMode bool = false

// promptsCmd represents the prompts command
var testCmd = &cobra.Command{
	Use:     "test <command>",
	Short:   "Run integration tests for the given command",
	Example: "cased-cli test auth instance.domain",
	// Requires at least one command to test.
	Args: cobra.MinimumNArgs(1),
	Run:  integrationTests,
}

func init() {
	rootCmd.AddCommand(testCmd)
}

func integrationTests(cmd *cobra.Command, args []string) {
	testMode = true

	switch args[0] {
	case "auth":
		// Forward [arguments] -> "cased-cli test auth [arguments]"
		login(cmd, args[1:])
	default:
		fmt.Println("Currently only auth command is supported.")
	}
}
