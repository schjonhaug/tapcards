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

	pubKey, _, err := ecdsa.RecoverCompact(newSig[:], messageDigest[:])

	return pubKey, err

}

/*
*
The first byte of each signature has rec_id encoded according to BIP-137.
* If the value is between 39 to 42 [39, 42], subtract 39 to get rec_id within the range of 0 to 3 [0, 3].
* If the value is [27, 30], subtract 27 to get rec_id within the range of [0, 3].
* Other values should not occur.
*/
func (tapProtocol *TapProtocol) recID(signature []byte) (byte, error) {
	if len(signature) == 0 {
		return 0, fmt.Errorf("empty signature")
	}

	firstByte := signature[0]
	fmt.Println("First byte before:", firstByte)

	//ecdsa.RecoverCompact subtracts 27 from the recID, so we need to offset it
	offset := 27

	switch {
	case firstByte >= 39 && firstByte <= 42:
		return firstByte - 39 + byte(offset), nil
	case firstByte >= 27 && firstByte <= 30:
		return firstByte - 27 + byte(offset), nil
	default:
		return firstByte, nil
	}

}
