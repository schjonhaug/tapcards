package main

import (
	"fmt"

	tapprotocol "github.com/schjonhaug/coinkite-tap-proto-go"
)

func main() {

	//cvc := "123456"

	var tapProtocol tapprotocol.TapProtocol
	// STATUS

	err := tapProtocol.Status()

	if err != nil {
		fmt.Println("YOU NEED TO CONNECT YOUR TAP CARD")
		fmt.Println(err)
		return
	}

	fmt.Println("Active slot", tapProtocol.ActiveSlot())
	fmt.Println(tapProtocol.NumberOfSlots())

	fmt.Println("Identity: " + tapProtocol.Identity())

	// Certificates

	err = tapProtocol.Certs()

	if err != nil {
		fmt.Println("Certs error")
		fmt.Println(err)
		return
	}

	/*paymentAddress, err := tapProtocol.Read(cvc)

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(paymentAddress)

	wif, err := tapProtocol.Unseal(cvc)

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("WIF encoded private key: ", wif)

	slot, err := tapProtocol.New(cvc)

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("Slot: ", slot)*/

}
