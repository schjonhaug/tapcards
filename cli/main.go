package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	tapprotocol "github.com/schjonhaug/coinkite-tap-proto-go"
	"github.com/skythen/apdu"
)

type Transport struct {
	connection net.Conn
}

func (transport *Transport) sendReceive(command []byte) ([]byte, error) {

	channel := make(chan []byte)

	go transport.Send(command, channel)

	data := <-channel

	return data, nil

}

func (transport *Transport) reader(r io.Reader, command any, channel chan []byte) {
	buf := make([]byte, 1024)
	_, err := r.Read(buf[:])

	if err != nil {
		print(err)
		return
	}

	channel <- buf

}

func (transport *Transport) Connect() {
	connection, err := net.Dial("unix", "/tmp/ecard-pipe")
	if err != nil {
		log.Fatal(err)
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

func main() {

	var transport Transport

	transport.Connect()
	defer transport.Disconnect()

	var tapProtocol tapprotocol.TapProtocol
	//cvc := "123456"

	argsWithoutProg := os.Args[1:]

	switch argsWithoutProg[0] {

	case "status":

		statusRequest, err := tapProtocol.StatusRequest()

		if err != nil {
			fmt.Println(err)
			return
		}

		// Remove APDU

		capdu, err := apdu.ParseCapdu(statusRequest)

		if err != nil {
			fmt.Println(err)
			return
		}

		response, err := transport.sendReceive(capdu.Data)

		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Println(response)

		//Wrap the response in apdu again

		rapdu := apdu.Rapdu{Data: response, SW1: 0x90, SW2: 0x00}

		bytes, err := rapdu.Bytes()

		if err != nil {
			fmt.Println(err)
			return
		}

		tapProtocol.ParseResponse(bytes)

		fmt.Println(tapProtocol)
		fmt.Println(tapProtocol.Satscard)

	/*case "read":

		paymentAddress, err := tapProtocol.Read()

		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Println(paymentAddress)

		fmt.Println(tapProtocol.Satscard)

	case "unseal":

		wif, err := tapProtocol.Unseal(cvc)

		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Println("WIF encoded private key: ", wif)

	case "certs":

		err := tapProtocol.Certs()

		if err != nil {
			fmt.Println("Certs error")
			fmt.Println(err)
			return
		}

	case "new":

		slot, err := tapProtocol.New(cvc)

		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Println("Slot: ", slot)

	case "wait":

		authDelay, err := tapProtocol.Wait()

		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Println("Auth Delay: ", authDelay)*/

	default:
		fmt.Println(fmt.Errorf("unknown command"))

	}

}
