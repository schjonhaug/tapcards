package tapprotocol

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

func (tapProtocol *TapProtocol) Certs() error {

	tapProtocol.transport.Connect()
	defer tapProtocol.transport.Disconnect()

	return tapProtocol.certs()

}

func (tapProtocol *TapProtocol) certs() error {

	tapProtocol.status()
	tapProtocol.read()

	//TODO

	fmt.Println("------------")
	fmt.Println("Certs")
	fmt.Println("------------")

	certsCommand := certsCommand{
		command{Cmd: "certs"},
	}

	data, err := tapProtocol.sendReceive(certsCommand)

	if err != nil {
		return err
	}

	switch data := data.(type) {
	case certificatesData:

		fmt.Println()
		fmt.Println("#########")
		fmt.Println("# CERTS #")
		fmt.Println("#########")

		fmt.Printf("Certificate chain: %x\n", data.CertificateChain[:])

		firstSignature := data.CertificateChain[0]

		r := new(btcec.ModNScalar)
		r.SetByteSlice(firstSignature[0:32])

		s := new(btcec.ModNScalar)
		s.SetByteSlice(firstSignature[32:])

		signature := ecdsa.NewSignature(r, s)

		checkData, err := tapProtocol.check()

		if err != nil {
			return err
		}

		message := append([]byte("OPENDIME"), tapProtocol.currentCardNonce[:]...)
		message = append(message, checkData.CardNonce[:]...)
		message = append(message, tapProtocol.currentSlotPublicKey[:]...)

		messageDigest := sha256.Sum256([]byte(message))

		fmt.Println(messageDigest)

		publicKey, err := btcec.ParsePubKey(tapProtocol.currentSlotPublicKey[:])

		if err != nil {
			return err
		}

		verified := signature.Verify(messageDigest[:], publicKey)

		if !verified {
			return errors.New("invalid signature")
		}

		tapProtocol.currentCardNonce = checkData.CardNonce

		return nil

	case ErrorData:
		fmt.Println("FOUND ERROR DATA")
		return errors.New(data.Error)

	default:
		return errors.New("undefined error")

	}

	//CertificateChain [][65]byte

	//factoryRootPublicKey = "03028a0e89e70d0ec0d932053a89ab1da7d9182bdc6d2f03e706ee99517d05d9e1"

	//return nil

}
