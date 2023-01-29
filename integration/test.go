package integration

import (
	"io"
	"log"
	"time"
)

// RunTest connect to the prompts specified in the integration test script
// then send the commands for execution.
// Any error will be detected by the ssh client (cmd/auth.go) on the stderr channel.
func RunTest(session io.WriteCloser) {
	sendBytes := func(data []byte) {
		n, err := session.Write(data)
		if n != len(data) || err != nil {
			log.Fatal("SSH write failed: ", err)
		}
	}
	for _, prompt := range TestAuthData.Prompts {
		sendBytes([]byte("/")) // Triggers list search (for Prompt)
		time.Sleep(2 * time.Second)
		sendBytes([]byte(prompt.Name)) // Look for a prompt matching this name.
		time.Sleep(2 * time.Second)
		sendBytes([]byte("\n")) // select Prompt
		time.Sleep(2 * time.Second)
		sendBytes([]byte("\r\n")) // send selection over SSH
		time.Sleep(5 * time.Second)

		for _, command := range prompt.Commands { // Send commands to the prompt.
			sendBytes([]byte(command.Cmd))
			sendBytes([]byte("\r\n"))
			time.Sleep(time.Second)
		}
		session.Write([]byte("exit\n"))
		time.Sleep(time.Second)
		log.Println("Integration test results: success")
	}
}
