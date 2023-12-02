package tapprotocol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
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

		r := new(btcec.ModNScalar)
		r.SetByteSlice(checkData.AuthSignature[0:32])

		s := new(btcec.ModNScalar)
		s.SetByteSlice(checkData.AuthSignature[32:])

		signature := ecdsa.NewSignature(r, s)

		publicKey, err := btcec.ParsePubKey(tapProtocol.cardPublicKey[:])

		verified := signature.Verify(messageDigest[:], publicKey)

		if !verified {
			return errors.New("invalid signature certs")
		}

		if err != nil {
			return err
		}

		for i := 0; i < len(data.CertificateChain); i++ {

			fmt.Println(i)
			fmt.Println("Certificate chain: ", data.CertificateChain[i])

			publicKey, err = tapProtocol.signatureToPublicKey(data.CertificateChain[i], publicKey)

			if err != nil {
				return err
			}

		}

		factoryRootPublicKey := []byte("03028a0e89e70d0ec0d932053a89ab1da7d9182bdc6d2f03e706ee99517d05d9e1")

		if !bytes.Equal(publicKey.SerializeCompressed(), factoryRootPublicKey) {
			return errors.New("invalid factory root public key")
		}

		tapProtocol.currentCardNonce = checkData.CardNonce

		return nil

	case ErrorData:
		fmt.Println("FOUND ERROR DATA")
		return errors.New(data.Error)

	default:
		return errors.New("undefined error")

	}

	//

}

func (tapProtocol *TapProtocol) recID(signature []byte) (byte, error) {
	if len(signature) == 0 {
		return 0, fmt.Errorf("empty signature")
	}

	firstByte := signature[0]

	fmt.Println("First byte:", firstByte)

	/*

			int header_num = header & 0xff;
		    if (header_num >= 39) {
		      header_num -= 12;
		    } else if (header_num >= 35) {
		      header_num -= 8;
		    } else if (header_num >= 31) {
		      header_num -= 4;
		    }
		    int rec_id = header_num - 27;
		    return rec_id;

	*/

	switch {
	case firstByte >= 39:
		firstByte -= 12

	case firstByte >= 35:
		firstByte -= 8

	case firstByte >= 31:
		firstByte -= 4
	}

	firstByte -= 27

	fmt.Println("First byte:", int(firstByte))

	return firstByte, nil

	/*
		switch {
		case firstByte >= 39 && firstByte <= 42:
			return int(firstByte - 39), nil
		case firstByte >= 27 && firstByte <= 30:
			return int(firstByte - 27), nil
		default:
			return 0, fmt.Errorf("invalid first byte value in signature")
		}*/
}

func (tapProtocol *TapProtocol) prependIntToBytes(slice []byte, value int) ([]byte, error) {
	buf := new(bytes.Buffer)
	// Use binary.BigEndian or binary.LittleEndian depending on your needs
	err := binary.Write(buf, binary.BigEndian, int64(value))
	if err != nil {
		return nil, err
	}
	// Prepend the byte representation of the integer
	return append(buf.Bytes(), slice...), nil
}

func (tapProtocol *TapProtocol) signatureToPublicKey(signature [65]byte, publicKey *secp256k1.PublicKey) (*secp256k1.PublicKey, error) {
	/*
		recId, err := tapProtocol.recID(signature[:])

		if err != nil {
			fmt.Println("REC ID ERROR")
			fmt.Println(err)
			return nil, err
		}

		newSig := append([]byte{recId}, signature[1:]...)

		//newSig, err := tapProtocol.prependIntToBytes(signature[:64], recId)

		if err != nil {
			fmt.Println("PREPEND INT TO BYTES ERROR")
			fmt.Println(err)
			return nil, err
		}*/

	//fmt.Println("New signature:", newSig)
	/*
		signature2, err := ecdsa.ParseDERSignature(newSig[:])

		if err != nil {
			fmt.Println("PARSE DER SIGNATURE ERROR")
			fmt.Println(err)
			return nil, err
		}

		fmt.Println(signature2)*/

	messageDigest := sha256.Sum256(publicKey.SerializeUncompressed())

	publicKey2, compressed, err := ecdsa.RecoverCompact(signature[:], messageDigest[:])

	if err != nil {
		fmt.Println("RECOVER COMPACT ERROR")
		fmt.Println(err)
		return nil, err
	}

	if compressed {
		fmt.Println("Compressed")
	}

	publicKeyHex := publicKey2.SerializeUncompressed()
	// Use publicKeyHex as needed

	fmt.Println("Public Key:", publicKeyHex)

	return publicKey2, nil

}
