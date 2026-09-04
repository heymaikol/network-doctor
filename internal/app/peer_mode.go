package app

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/x/term"
	"github.com/heymaikol/network-doctor/internal/peer"
	"github.com/heymaikol/network-doctor/internal/textsafe"
)

type peerListenList []string

func (addresses *peerListenList) String() string { return strings.Join(*addresses, ",") }

func (addresses *peerListenList) Set(value string) error {
	address, family, err := peer.NormalizeListenAddress(value)
	if err != nil {
		return errors.New("want an exact IP:port (port 0 asks the kernel to choose; a link-local address needs its %zone)")
	}
	if len(*addresses) >= 2 {
		return errors.New("at most one IPv4 and one IPv6 peer listener are allowed")
	}
	for _, existing := range *addresses {
		_, existingFamily, _ := peer.NormalizeListenAddress(existing)
		if existingFamily == family {
			return fmt.Errorf("an %s peer listener is already configured", family)
		}
	}
	*addresses = append(*addresses, address)
	return nil
}

var readPeerPairing = readPeerPairingFromStdin
var connectPeer = peer.Connect

func readPeerPairingFromStdin(prompt io.Writer) (string, error) {
	fmt.Fprint(prompt, "Temporary pairing string: ")
	var (
		value []byte
		err   error
	)
	if term.IsTerminal(os.Stdin.Fd()) {
		value, err = term.ReadPassword(os.Stdin.Fd())
		fmt.Fprintln(prompt)
	} else {
		reader := bufio.NewReaderSize(io.LimitReader(os.Stdin, peer.MaxPairingCodeSize+1), peer.MaxPairingCodeSize+1)
		var line string
		line, err = reader.ReadString('\n')
		if errors.Is(err, io.EOF) {
			err = nil
		}
		value = []byte(line)
	}
	value = bytes.TrimSpace(value)
	if err != nil {
		return "", errors.New("could not read the pairing string")
	}
	if len(value) == 0 || len(value) > peer.MaxPairingCodeSize {
		return "", errors.New("invalid pairing string length")
	}
	return string(value), nil
}

func runPeerListener(parent context.Context, addresses []string, options peer.Options, jsonOut bool, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()
	listener, err := peer.NewListener(ctx, addresses, options)
	if err != nil {
		fmt.Fprintln(stderr, "netdoc:", textsafe.Clean(err.Error()))
		return 1
	}
	defer func() { _ = listener.Close() }()
	ready := stderr
	fmt.Fprintln(ready, "Peer session ready")
	for _, endpoint := range listener.Endpoints() {
		fmt.Fprintln(ready, "Direct endpoint:", endpoint)
	}
	fmt.Fprintf(ready, "Temporary pairing string (expires %s):\n%s\n", listener.Expires().UTC().Format(time.RFC3339), listener.PairingCode())
	fmt.Fprintln(ready, "The connector must reach at least one direct endpoint. Waiting for one peer...")
	result, err := listener.Run(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "netdoc:", textsafe.Clean(err.Error()))
		return 1
	}
	return emitPeerResult(result, jsonOut, stdout, stderr)
}

func runPeerConnector(parent context.Context, options peer.Options, jsonOut bool, stdout, stderr io.Writer) int {
	code, err := readPeerPairing(stderr)
	if err != nil {
		fmt.Fprintln(stderr, "netdoc:", err)
		return 2
	}
	ctx, stop := signal.NotifyContext(parent, os.Interrupt, syscall.SIGTERM)
	defer stop()
	if !jsonOut {
		fmt.Fprintln(stdout, "Connecting to peer")
		fmt.Fprintln(stdout, "Running two-ended diagnosis...")
	}
	result, err := connectPeer(ctx, code, options)
	if err != nil {
		fmt.Fprintln(stderr, "netdoc:", textsafe.Clean(err.Error()))
		if peer.IsPairingError(err) {
			return 2
		}
		return 1
	}
	return emitPeerResult(result, jsonOut, stdout, stderr)
}

func emitPeerResult(result peer.Result, jsonOut bool, stdout, stderr io.Writer) int {
	if jsonOut {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(result); err != nil {
			fmt.Fprintln(stderr, "netdoc:", err)
			return 1
		}
	} else {
		fmt.Fprintln(stdout, "Connected to peer")
		fmt.Fprintln(stdout, result.Diagnosis.Summary)
		fmt.Fprintf(stdout, "Local: %s %s (%s)\n", result.Local.Role, result.Local.Name, strings.Join(result.Local.ListenAddresses, ", "))
		fmt.Fprintf(stdout, "Remote: %s %s (%s)\n", result.Remote.Role, result.Remote.Name, strings.Join(result.Remote.ListenAddresses, ", "))
		fmt.Fprintln(stdout, "Observations:")
		for _, observation := range result.Observations {
			line := fmt.Sprintf("  [%s] %s %s", observation.Status, observation.Direction, observation.Family)
			if observation.Destination != "" {
				line += " to " + observation.Destination
			}
			if observation.Cause != "" {
				line += ": " + observation.Cause
			}
			fmt.Fprintln(stdout, line)
		}
		if result.Diagnosis.Ambiguous {
			fmt.Fprintln(stdout, "Ambiguous: the observations do not identify one unique cause.")
			for _, alternative := range result.Diagnosis.Alternatives {
				fmt.Fprintln(stdout, "  Possible:", alternative)
			}
		}
	}
	if result.OK {
		return 0
	}
	return 1
}
