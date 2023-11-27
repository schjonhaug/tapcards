package main

import (
	"fmt"

	tapprotocol "github.com/schjonhaug/coinkite-tap-proto-go"
)

func main() {

	cvc := "123456"

	var tapProtocol tapprotocol.TapProtocol
	// STATUS

	tapProtocol.Status()
	fmt.Println("Active slot", tapProtocol.ActiveSlot())
	//fmt.Println(tapProtocol.NumberOfSlots())

	fmt.Println("Identity: " + tapProtocol.Identity())

	tapProtocol.ReadCurrentPaymentAddress(cvc)

	wif, err := tapProtocol.Unseal(cvc)

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("WIF encoded private key: ", wif)

	// Certificates

	// TODO tapProtocol.Certificates()

	tapProtocol.New(cvc)

}
