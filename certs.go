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

		nonce, err := tapProtocol.createNonce()

		if err != nil {
			return err
		}

		checkData, err := tapProtocol.check(nonce)

		if err != nil {
			return err
		}

		message := append([]byte("OPENDIME"), tapProtocol.currentCardNonce[:]...)
		message = append(message, nonce[:]...)

		var zeroArray [33]byte
		if tapProtocol.currentSlotPublicKey != zeroArray {
			fmt.Println("Adding current slot public key")
			message = append(message, tapProtocol.currentSlotPublicKey[:]...)
		}

		messageDigest := sha256.Sum256([]byte(message))

		if err != nil {
			return err
		}

		r := new(btcec.ModNScalar)
		r.SetByteSlice(checkData.AuthSignature[0:32])

		s := new(btcec.ModNScalar)
		s.SetByteSlice(checkData.AuthSignature[32:])

		signature := ecdsa.NewSignature(r, s)

		publicKey, err := btcec.ParsePubKey(tapProtocol.cardPublicKey[:])

		verified := signature.Verify(messageDigest[:], publicKey)

		if !verified {
			return errors.New("invalid signature certs")
		} else {
			fmt.Println("Signature verified")
		}

		if err != nil {
			return err
		}
		/*
			for i := 0; i < len(data.CertificateChain); i++ {

				fmt.Println(i)
				fmt.Println("Certificate chain: ", data.CertificateChain[i])

				x := sha256.Sum256(append(publicKey.SerializeUncompressed(), data.CertificateChain[i][:]...))

				publicKey, err := btcec.ParsePubKey(x[:])

				if err != nil {
					return err
				}

			}
		*/
		tapProtocol.currentCardNonce = checkData.CardNonce

		return nil

	case ErrorData:
		fmt.Println("FOUND ERROR DATA")
		return errors.New(data.Error)

	default:
		return errors.New("undefined error")

	}

	//factoryRootPublicKey = "03028a0e89e70d0ec0d932053a89ab1da7d9182bdc6d2f03e706ee99517d05d9e1"

}
