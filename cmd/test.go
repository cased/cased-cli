package cmd

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

// Set when running cased-cli in test mode: cased-cli test <command> [command_args...]
var testMode bool = false
var scriptFile string

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
	testCmd.Flags().StringVarP(&scriptFile, "script", "s", "", "Script file for integration tests")
	log.Default()
	rootCmd.AddCommand(testCmd)
}

func integrationTests(cmd *cobra.Command, args []string) {
	testMode = true

	if scriptFile != "" {
		loadTestScript(args[0])
	}

	switch args[0] {
	case "auth":
		// Forward [arguments] -> "cased-cli test auth [arguments]"
		login(cmd, args[1:])
	default:
		fmt.Println("Currently only auth command is supported.")
	}
}

// loadTestScript attempts to load the YAML script file and parse it according to
// the specified command.
func loadTestScript(command string) {
	sf, err := os.Open(scriptFile)
	if err != nil {
		log.Fatalf("Unable to open script file %q: %v\n", scriptFile, err)
	}
	defer sf.Close()

	data, err := ioutil.ReadAll(sf)
	if err != nil {
		log.Fatalf("Unable to read script file %q: %v\n", scriptFile, err)
	}

	switch command {
	case "auth":
		err = yaml.Unmarshal(data, &TestAuthData)
		if err != nil {
			log.Fatalf("Invalid script syntax\nCommand: %s\nScript: %s\nError: %v\n",
				command, scriptFile, err)
		}
	default:
		log.Fatalf("Unsupported command: %s\n", command)
	}

	log.Println("Running Integration tests...")
	log.Println("Test script: ", scriptFile)
	log.Println("Test command:", command)
}
