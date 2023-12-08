package tapprotocol

import (
	"crypto/sha256"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2/ecdsa"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func (tapProtocol *TapProtocol) CertsRequest() ([]byte, error) {

	fmt.Println("------------")
	fmt.Println("Certs")
	fmt.Println("------------")

	if tapProtocol.currentCardNonce == [16]byte{} {
		tapProtocol.Queue.Enqueue("status")
	}

	tapProtocol.Queue.Enqueue("certs")
	tapProtocol.Queue.Enqueue("read")
	tapProtocol.Queue.Enqueue("check")

	return tapProtocol.nextCommand()

}

func (tapProtocol *TapProtocol) certsRequest() ([]byte, error) {

	certsCommand := certsCommand{
		Command{Cmd: "certs"},
	}

	return tapProtocol.ApduWrap(certsCommand)
}

func (tapProtocol *TapProtocol) parseCertsData(certsData certsData) error {

	fmt.Println()
	fmt.Println("#########")
	fmt.Println("# CERTS #")
	fmt.Println("#########")

	tapProtocol.certificateChain = certsData.CertificateChain

	return nil

}

func (tapProtocol *TapProtocol) signatureToPublicKey(signature [65]byte, publicKey *secp256k1.PublicKey) (*secp256k1.PublicKey, error) {

	fmt.Println("Signature:", signature[:])

	messageDigest := sha256.Sum256(publicKey.SerializeCompressed())

	recId, err := tapProtocol.recID(signature[:])

	if err != nil {
		return nil, err
	}

	fmt.Println("RecID:", recId)

	newSig := append([]byte{recId}, signature[1:]...)
	//newSig := append(signature[1:], []byte{recId}...)
	fmt.Println("newSig:", newSig)

	pubKey, _, err := ecdsa.RecoverCompact(signature[:], messageDigest[:])

	return pubKey, err

}

func (tapProtocol *TapProtocol) recID(signature []byte) (byte, error) {
	if len(signature) == 0 {
		return 0, fmt.Errorf("empty signature")
	}

	firstByte := signature[0]
	fmt.Println("First byte before:", firstByte)
	/*
		switch {
		case firstByte >= 39 && firstByte <= 42:
			return byte(firstByte - 39), nil
		case firstByte >= 27 && firstByte <= 30:
			return byte(firstByte - 27), nil
		default:
			return 0, fmt.Errorf("invalid first byte value in signature")
		}
	*/
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

	fmt.Println("First byte after:", int(firstByte))

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
