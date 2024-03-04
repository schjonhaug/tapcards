package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/schjonhaug/tapcards"
	"github.com/skythen/apdu"
)

func die(err error) {
	fmt.Println(err)
	os.Exit(1)
}

type Transport struct {
	connection net.Conn
}

func (transport *Transport) sendRequest(command []byte) ([]byte, error) {

	unwrappedCommand, err := transport.unwrapApdu(command)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	channel := make(chan []byte)

	go transport.Send(unwrappedCommand, channel)

	data := <-channel

	wrappedCommand, err := transport.wrapApdu(data)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return wrappedCommand, nil

}

func (transport *Transport) reader(r io.Reader, command any, channel chan []byte) {
	buf := make([]byte, 1024)
	_, err := r.Read(buf[:])

	if err != nil {
		die(err)
	}

	channel <- buf

}

func (transport *Transport) Connect() {
	connection, err := net.Dial("unix", "/tmp/ecard-pipe")
	if err != nil {
		die(err)
	}
	transport.connection = connection
}

func (transport Transport) Disconnect() {
	transport.connection.Close()
}

func (transport Transport) Send(command []byte, channel chan []byte) {

	go transport.reader(transport.connection, command, channel)
	_, err := transport.connection.Write(command)

	if err != nil {
		log.Fatal("write error:", err)
	}

	time.Sleep(100 * time.Millisecond)

}

func (transport *Transport) unwrapApdu(data []byte) ([]byte, error) {

	capdu, err := apdu.ParseCapdu(data)

	return capdu.Data, err

}

func (transport *Transport) wrapApdu(data []byte) ([]byte, error) {

	//Wrap the response in apdu again

	rapdu := apdu.Rapdu{Data: data, SW1: 0x90, SW2: 0x00}

	return rapdu.Bytes()

}

func (transport *Transport) loop(request []byte, fn2 func(response []byte) ([]byte, error)) {

	for request != nil {

		response, err := transport.sendRequest(request)

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

func main() {

	argsWithoutProg := os.Args[1:]

	if len(argsWithoutProg) == 0 {
		die(errors.New("command required"))
	}

	var transport Transport

	cvc := "123456"

	transport.Connect()
	defer transport.Disconnect()

	var satscard tapcards.Satscard

	tapcards.UseEmulator()
	tapcards.EnableDebugLogging()

	var request []byte
	var err error

	switch argsWithoutProg[0] {

	case "status":
		request, err = satscard.StatusRequest()
	case "read":
		request, err = satscard.ReadRequest()
	case "unseal":
		request, err = satscard.UnsealRequest(cvc)
	case "certs":
		request, err = satscard.CertsRequest()
	case "new":
		request, err = satscard.NewRequest(cvc)
	case "wait":
		request, err = satscard.WaitRequest()

	default:
		die(errors.New("unknown command"))

	}

	if err != nil {
		die(err)
	}

	transport.loop(request, satscard.ParseResponse)

	fmt.Println(satscard)

}
