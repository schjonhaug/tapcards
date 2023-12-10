package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/ebfe/scard"

	tapprotocol "github.com/schjonhaug/coinkite-tap-proto-go"
)

func die(err error) {
	fmt.Println(err)
	os.Exit(1)
}

func waitUntilCardPresent(ctx *scard.Context, readers []string) (int, error) {
	rs := make([]scard.ReaderState, len(readers))
	for i := range rs {
		rs[i].Reader = readers[i]
		rs[i].CurrentState = scard.StateUnaware
	}

	for {
		for i := range rs {
			if rs[i].EventState&scard.StatePresent != 0 {
				return i, nil
			}
			rs[i].CurrentState = rs[i].EventState
		}
		err := ctx.GetStatusChange(rs, -1)
		if err != nil {
			return -1, err
		}
	}
}

func main() {

	var tapProtocol tapprotocol.TapProtocol

	tapProtocol.EnableDebugLogging()

	// Establish a context
	ctx, err := scard.EstablishContext()
	if err != nil {
		die(err)
	}
	defer ctx.Release()

	// List available readers
	readers, err := ctx.ListReaders()
	if err != nil {
		die(err)
	}

	fmt.Printf("Found %d readers:\n", len(readers))
	for i, reader := range readers {
		fmt.Printf("[%d] %s\n", i, reader)
	}

	if len(readers) > 0 {

		fmt.Println("Waiting for a Card")
		index, err := waitUntilCardPresent(ctx, readers)
		if err != nil {
			die(err)
		}

		// Connect to card
		fmt.Println("Connecting to card in ", readers[index])
		card, err := ctx.Connect(readers[index], scard.ShareExclusive, scard.ProtocolAny)
		if err != nil {
			die(err)
		}
		defer card.Disconnect(scard.ResetCard)

		fmt.Println("Card status:")
		status, err := card.Status()
		if err != nil {
			die(err)
		}

		fmt.Printf("\treader: %s\n\tstate: %x\n\tactive protocol: %x\n\tatr: % x\n",
			status.Reader, status.State, status.ActiveProtocol, status.Atr)

		// INIT

		cmd, err := tapProtocol.InitRequest()

		if err != nil {
			die(err)
		}

		fmt.Println("Transmit:")
		fmt.Printf("\tc-apdu: % x\n", cmd)
		rsp, err := card.Transmit(cmd)
		if err != nil {
			die(err)
		}
		fmt.Printf("\tr-apdu: % x\n", rsp)

		_, err = tapProtocol.ParseResponse(rsp)

		if err != nil {
			die(err)
		}

		fmt.Println("Satscard", tapProtocol.Satscard)

		// READ FROM COMMAND LINE

		argsWithoutProg := os.Args[1:]

		var request []byte

		switch argsWithoutProg[0] {

		case "status":
			request, err = tapProtocol.StatusRequest()
		case "read":
			request, err = tapProtocol.ReadRequest()
		case "unseal":
			request, err = tapProtocol.UnsealRequest(argsWithoutProg[1])
		case "certs":
			request, err = tapProtocol.CertsRequest()
		case "new":
			request, err = tapProtocol.NewRequest(argsWithoutProg[1])
		case "wait":
			request, err = tapProtocol.WaitRequest()

		default:
			die(errors.New("unknown command"))

		}

		if err != nil {
			die(err)
		}

		loop(card, request, tapProtocol.ParseResponse)

		fmt.Println("Satscard", tapProtocol.Satscard)

	}

}

func loop(card *scard.Card, request []byte, fn2 func(response []byte) ([]byte, error)) {

	for request != nil {

		response, err := card.Transmit(request)

		if err != nil {
			fmt.Println(err)
			return
		}

		request, err = fn2(response)

		if err != nil {
			fmt.Println(err)
			return
		}

	}

}
