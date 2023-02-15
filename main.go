package main

import (
	"fmt"
)

var tapProtocol TapProtocol

func main() {

	// STATUS

	tapProtocol.Status()
	fmt.Println(tapProtocol.Identity())
	fmt.Println(tapProtocol.ActiveSlot())
	fmt.Println(tapProtocol.NumberOfSlots())

	wif, err := tapProtocol.Unseal("123456")

	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(*wif)

	//tapProtocol.Read("123456")

	// Certificates
	/*
		certificatesCommand := CertificatesCommand{
			command{Cmd: "certs"},
		}
		sendReceive(certificatesCommand)

		return


		// NEW

		command = Command{Cmd: "new"}

		auth, err = tapProtocol.Authenticate("123456", command)

		if err != nil {
			fmt.Println(err)
			return
		}

		newCommand := NewCommand{
			Command: command,
			Slot:    tapProtocol.ActiveSlot,
			Auth:    *auth}

		sendReceive(newCommand)
	*/

}
