package integration

// TestPrompt and TestAuth represent data loaded from integration test script.
type TestPrompt struct {
	Name     string // prompt name
	Matches  string
	Commands []struct {
		Cmd      string // command to execute
		Expected string // expected output
	}
}

type TestAuth struct {
	Prompts []TestPrompt
}

// TestAuthData stores integration test script data for testing the auth command.
var TestAuthData TestAuth
