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

	tapProtocol.Unseal("123456")

	// Certificates
	/*
		certificatesCommand := CertificatesCommand{
			command{Cmd: "certs"},
		}
		sendReceive(certificatesCommand)

		return

		// READ

		command := Command{Cmd: "read"}

		auth, err := tapProtocol.Authenticate("123456", command)

		if err != nil {
			fmt.Println(err)
			return
		}

		// Create nonce

		// first step is to create a slice of bytes with the desired length
		nonce := make([]byte, 16)
		// then we can call rand.Read.
		_, err = rand.Read(nonce)

		fmt.Printf("\nNONCE: %x", nonce)

		tapProtocol.Nonce = nonce

		if err != nil {
			log.Fatalf("error while generating random string: %s", err)
		}

		readCommand := ReadCommand{
			Command: command,
			Auth:    *auth,
			Nonce:   nonce,
		}

		sendReceive(readCommand)

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
