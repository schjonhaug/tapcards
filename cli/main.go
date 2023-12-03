package main

import (
	"fmt"
	"os"

	tapprotocol "github.com/schjonhaug/coinkite-tap-proto-go"
)

func main() {

	var tapProtocol tapprotocol.TapProtocol
	cvc := "123456"

	argsWithoutProg := os.Args[1:]

	switch argsWithoutProg[0] {

	case "status":

		err := tapProtocol.Status()

		if err != nil {

			fmt.Println(err)
			return
		}

		fmt.Println(tapProtocol.Satscard)

	case "read":

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

		fmt.Println("Auth Delay: ", authDelay)

	default:
		fmt.Println(fmt.Errorf("unknown command"))

	}

}
