package tapprotocol

import (
	"crypto/sha256"

	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func (tapProtocol *TapProtocol) Certs() error {

	//TODO tapProtocol.transport.Connect()
	//TODO defer tapProtocol.transport.Disconnect()

	return tapProtocol.certs()

}

func (tapProtocol *TapProtocol) certs() error {
	/*
		if tapProtocol.currentCardNonce == [16]byte{} {
			// TODO		tapProtocol.status()
		}

		//TODO tapProtocol.read()

		//TODO

		fmt.Println("------------")
		fmt.Println("Certs")
		fmt.Println("------------")

		certsCommand := certsCommand{
			Command{Cmd: "certs"},
		}

		data, err := tapProtocol.sendReceive(certsCommand)

		if err != nil {
			return err
		}

		certsData, ok := data.(certsData)

		if !ok {
			return errors.New("incorrect data type")
		}
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

		if tapProtocol.currentSlotPublicKey != [33]byte{} {
			fmt.Println("Adding current slot public key")
			message = append(message, tapProtocol.currentSlotPublicKey[:]...)
		}

		messageDigest := sha256.Sum256([]byte(message))

		r := new(btcec.ModNScalar)
		r.SetByteSlice(checkData.AuthSignature[0:32])

		s := new(btcec.ModNScalar)
		s.SetByteSlice(checkData.AuthSignature[32:])

		signature := ecdsa.NewSignature(r, s)

		publicKey, err := btcec.ParsePubKey(tapProtocol.cardPublicKey[:])

		if err != nil {
			return err
		}

		verified := signature.Verify(messageDigest[:], publicKey)

		if !verified {
			return errors.New("invalid signature certs")
		}

		for i := 0; i < len(certsData.CertificateChain); i++ {

			publicKey, err = tapProtocol.signatureToPublicKey(certsData.CertificateChain[i], publicKey)

			if err != nil {
				return err
			}

		}

		hexString := "022b6750a0c09f632df32afc5bef66568667e04b2e0f57cb8640ac5a040179442b" // bogus
		//hexString := "03028a0e89e70d0ec0d932053a89ab1da7d9182bdc6d2f03e706ee99517d05d9e1" // real

		// Convert hex string to bytes
		factoryRootPublicKey, err := hex.DecodeString(hexString)
		if err != nil {
			log.Fatal(err)
		}

		if !bytes.Equal(publicKey.SerializeCompressed(), factoryRootPublicKey) {
			return errors.New("counterfeit card: invalid factory root public key")
		} else {
			fmt.Println("factoryRootPublicKey matched")
		}

		tapProtocol.currentCardNonce = checkData.CardNonce
	*/
	return nil

}

func (tapProtocol *TapProtocol) signatureToPublicKey(signature [65]byte, publicKey *secp256k1.PublicKey) (*secp256k1.PublicKey, error) {

	messageDigest := sha256.Sum256(publicKey.SerializeCompressed())

	pubKey, _, err := ecdsa.RecoverCompact(signature[:], messageDigest[:])

	if err != nil {
		return nil, err
	}

	return pubKey, nil

}
