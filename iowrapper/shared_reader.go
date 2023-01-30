package iowrapper

import (
	"bufio"
	"errors"
	"io"
	"sync/atomic"
)

// SharedReader wraps reads from any io.Reader object, it was designed
// to solve a problem that arises when writting bubbletea apps, which
// can be described as follows:
//    1. The app is reading and processing input (stdin, etc), then the app
// starts a bubbletea program (tea.NewProgram(...).Start()). When users type
// some input, it may happen that the app captures the input first, leaving
// bubbletea hanging (bubbletea didn't consume the input, so no updates take place).
//    2. Similarly, if a bubbletea program is running and the app decides to
// stop it, it may happen that bubbletea may have consumed the input before the app,
// forcing users to type it again.
//
// To solve this problem, we implement a reader object that has two states,
// attached/detached, when we switch from one state to another, we check if there
// is some input queued in the previous stated and forward it to a channel from
// which this data can be consumed.

// SharedReader implements the io.Reader interface: https://pkg.go.dev/io#Reader,
// which allows us to provide it as the input reader for bubbletea:
// e.g tea.NewProgram(m, tea.WithInput(stdinReader{})
//
// At any given time, SharedReader can be in one of two modes:
//
//	1: bubbletea mode: In this mode, we say we are "detached" from stdin,
//	   all input is read and processed by the bubbletea library.
//
//	2: normal mode: In this mode, cased-cli consumes stdin input normally.
type SharedReader struct {
	detached atomic.Bool   // if detached, input is being consumed by bubbletea.
	Ch       chan []byte   // Send all data read from source input to this channel.
	reader   *bufio.Reader // Read input using a buffered reader, which allows to "unread" input.
	// keep last input read, when we switch from bubbletea to normal mode
	// if there was any pending data read, we forward it to the Ch channel.
	// This allows cased-cli to not miss that input.
	lastInput   []byte
	readOps     uint64
	consumedOps uint64
}

// New creates a new SharedReader instance which consumes input from the
// io.Reader object given, e.g. os.Stdin.
func New(input io.Reader) *SharedReader {
	return &SharedReader{
		reader: bufio.NewReader(input),
		Ch:     make(chan []byte),
	}
}

// Detach switches input mode from normal to bubbletea.
func (r *SharedReader) Detach() {
	r.detached.Store(true)
	select {
	// input not consumed by cased-cli, forward it to bubbletea.
	case <-r.Ch:
		r.reader.UnreadByte()
	default:
		return
	}
}

func (r *SharedReader) hasDataQueued() bool {
	return atomic.LoadUint64(&r.consumedOps) != atomic.LoadUint64(&r.readOps)
}

// Attach switches input mode from bubbletea to normal
func (r *SharedReader) Attach() {
	r.detached.Store(false)
	if r.hasDataQueued() {
		// Send non-consumed input read from bubbletea back to our app
		r.Ch <- r.lastInput
	}
	r.lastInput = nil
}

func (r *SharedReader) IsDetached() bool {
	return r.detached.Load()
}

// ReadLoop forward data read to the inputChan channel.
// This blocks, it's meant to be running in a separate goroutine.
func (r *SharedReader) ReadLoop() {
	var buffer [32]byte
	for {
		n, err := r.reader.Read(buffer[:])
		if err != nil {
			close(r.Ch)
			return
		}
		// Keep last input read from bubbletea app
		// When we close the bubbletea app (snippets), send the last
		// input back to our app so we don't lose it.
		if r.detached.Load() {
			// cap on nil slice == 0
			if cap(r.lastInput) < n {
				r.lastInput = make([]byte, n)
			}
			copy(r.lastInput, buffer[:n])
		}
		atomic.AddUint64(&r.readOps, 1)
		r.Ch <- buffer[:n]
	}
}

func (r *SharedReader) Read(p []byte) (n int, err error) {
	b, ok := <-r.Ch

	if !ok {
		return 0, errors.New("stdin channel is closed")
	}

	atomic.AddUint64(&r.consumedOps, 1)
	return copy(p, b), nil
}
