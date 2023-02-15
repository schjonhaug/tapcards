//package main

package main

import (
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"math/big"
	"strings"
)

// TAP PROTOCOL

type TapProtocol struct {
	nonce            []byte
	currentCardNonce [16]byte
	cardPublicKey    [33]byte
	sessionKey       []byte
	activeSlot       int
	numberOfSlots    int
	transport        Transport
}

// Human friendly active slot number
func (tapProtocol *TapProtocol) ActiveSlot() int {
	return tapProtocol.activeSlot + 1
}

func (tapProtocol *TapProtocol) NumberOfSlots() int {
	return tapProtocol.numberOfSlots
}

func (tapProtocol *TapProtocol) Identity() string {
	// convert pubkey into a hash formatted for humans
	// - sha256(compressed-pubkey)
	// - skip first 8 bytes of that (because that's revealed in NFC URL)
	// - base32 and take first 20 chars in 4 groups of five
	// - insert dashes
	// - result is 23 chars long

	if len(tapProtocol.cardPublicKey) != 33 {
		panic("expecting compressed pubkey")
	}

	checksum := sha256.Sum256(tapProtocol.cardPublicKey[:])

	base32String := base32.StdEncoding.EncodeToString(checksum[8:])

	// Only keep the first 20 characters
	s := base32String[:20]

	// Split the string into groups of 5 characters
	var groups []string
	for i := 0; i < len(s); i += 5 {
		end := i + 5
		if end > len(s) {
			end = len(s)
		}
		groups = append(groups, s[i:end])
	}

	// Join the groups with dashes
	return strings.Join(groups, "-")

}

func (tapProtocol *TapProtocol) authenticate(cvc string, command command) (*auth, error) {

	fmt.Println("\n########")
	fmt.Println("# AUTH #")
	fmt.Println("########")

	fmt.Println("CVC:", cvc)
	fmt.Println("Command:", command.Cmd)

	cardPublicKey, err := secp256k1.ParsePubKey(tapProtocol.cardPublicKey[:])
	if err != nil {
		return nil, err
	}

	// Derive an ephemeral public/private keypair for performing ECDHE with
	// the recipient.
	ephemeralPrivateKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {

		return nil, err
	}

	ephemeralPublicKey := ephemeralPrivateKey.PubKey().SerializeCompressed()

	fmt.Print("\n")
	fmt.Printf("Ephemeral Public Key: %x\n", ephemeralPublicKey)

	// Using ECDHE, derive a shared symmetric key for encryption of the plaintext.
	sessionKey := sha256.Sum256(generateSharedSecret(ephemeralPrivateKey, cardPublicKey))

	fmt.Printf("Session Key:  %x\n", sessionKey)
	fmt.Printf("CurrentCardNonce:  %x\n", tapProtocol.currentCardNonce)

	md := sha256.Sum256(append(tapProtocol.currentCardNonce[:], []byte(command.Cmd)...))

	mask := xor(sessionKey[:], md[:])[:len(cvc)]

	xcvc := xor([]byte(cvc), mask)

	fmt.Printf("xcvc %x\n", xcvc)

	auth := auth{EphemeralPubKey: ephemeralPublicKey, XCVC: xcvc}

	return &auth, nil

}

// STATUS
func (tapProtocol *TapProtocol) Status() {

	statusCommand := statusCommand{command{Cmd: "status"}}

	tapProtocol.sendReceive(statusCommand)

}

// UNSEAL
func (tapProtocol *TapProtocol) Unseal(cvc string) /* (*UnsealData, Error)*/ {

	command := command{Cmd: "unseal"}

	auth, err := tapProtocol.authenticate(cvc, command)

	if err != nil {
		fmt.Println(err)
		return
	}

	unsealCommand := unsealCommand{
		command: command,
		auth:    *auth,
		Slot:    tapProtocol.activeSlot,
	}

	tapProtocol.sendReceive(unsealCommand)

}

func xor(a, b []byte) []byte {

	if len(a) != len(b) {
		panic("input slices have different lengths")
	}
	c := make([]byte, len(a))
	for i := range a {
		c[i] = a[i] ^ b[i]
	}
	return c
}

// generateSharedSecret generates a shared secret based on a private key and a
// public key using Diffie-Hellman key exchange (ECDH) (RFC 5903).
// RFC5903 Section 9 states we should only return x.
//
// It is recommended to securely hash the result before using as a cryptographic
// key.
func generateSharedSecret(privateKey *secp256k1.PrivateKey, publicKey *secp256k1.PublicKey) []byte {

	var point, result secp256k1.JacobianPoint
	publicKey.AsJacobian(&point)
	secp256k1.ScalarMultNonConst(&privateKey.Key, &point, &result)
	result.ToAffine()
	xBytes := result.X.Bytes()

	fmt.Println("Y:", publicKey.Y().Text(2))

	y := new(big.Int)
	y.SetBytes(result.Y.Bytes()[:])

	// Perform a bitwise AND with 0x01
	andResult := new(big.Int).And(y, big.NewInt(0x01))

	// Perform a bitwise OR with 0x02
	orResult := new(big.Int).Or(andResult, big.NewInt(0x02))

	even := orResult.Bytes()

	sharedSecret := append(even, xBytes[:]...)

	return sharedSecret
}

func (tapProtocol *TapProtocol) sendReceive(command any) {

	channel := make(chan any)

	go tapProtocol.transport.Send(command, channel)

	data := <-channel

	switch data := data.(type) {
	case StatusData:

		fmt.Println("##########")
		fmt.Println("# STATUS #")
		fmt.Println("##########")

		fmt.Println("Proto:     ", data.Proto)
		fmt.Println("Birth:     ", data.Birth)
		fmt.Println("Slots:     ", data.Slots)
		fmt.Println("Addr:      ", data.Address)
		fmt.Println("Ver:       ", data.Version)
		fmt.Printf("Pubkey:     %x\n", data.PublicKey)
		fmt.Printf("Card Nonce: %x\n", data.CardNonce)

		tapProtocol.cardPublicKey = data.PublicKey
		tapProtocol.currentCardNonce = data.CardNonce
		tapProtocol.activeSlot = data.Slots[0]
		tapProtocol.numberOfSlots = data.Slots[1]

	case UnsealData:

		fmt.Println("##########")
		fmt.Println("# UNSEAL #")
		fmt.Println("##########")

		fmt.Println("Slot:             ", data.Slot)
		fmt.Printf("Private Key:       %x\n", data.PrivateKey)
		fmt.Printf("Public Key:        %x\n", data.PublicKey)
		fmt.Printf("Master Public Key: %x\n", data.MasterPublicKey)
		fmt.Printf("Chain Code:        %x\n", data.ChainCode)
		fmt.Printf("Card Nonce:        %x\n", data.CardNonce)

		tapProtocol.currentCardNonce = data.CardNonce

		// Increase active slot

		if tapProtocol.activeSlot < tapProtocol.numberOfSlots {
			tapProtocol.activeSlot++
		}

	case NewData:

		fmt.Println("#######")
		fmt.Println("# NEW #")
		fmt.Println("#######")

		fmt.Println("Slot:             ", data.Slot)

		tapProtocol.currentCardNonce = data.CardNonce

	case ReadData:

		fmt.Println("########")
		fmt.Println("# READ #")
		fmt.Println("########")

		fmt.Printf("Signature: %x\n", data.Signature)
		fmt.Printf("Public Key: %x\n", data.PublicKey)

		// Verify public key with signature

		message := append([]byte("OPENDIME"), tapProtocol.currentCardNonce[:]...)
		message = append(message, tapProtocol.nonce[:]...)
		message = append(message, []byte{byte(tapProtocol.activeSlot)}...)

		messageDigest := sha256.Sum256([]byte(message))

		fmt.Printf("message digest: %x\n", messageDigest)

		recId := data.Signature[0]
		fmt.Printf("REC ID: %d\n", recId)
		fmt.Println("REC ID: ", recId)

		r := new(btcec.ModNScalar)
		ok := r.SetByteSlice(data.Signature[0:31])

		println("OK ", ok)

		s := new(btcec.ModNScalar)
		ok = s.SetByteSlice(data.Signature[32:])
		println("OK ", ok)

		signature := ecdsa.NewSignature(r, s)

		fmt.Printf("signature: %x\n", signature.Serialize())
		/*
			signature2, err := ecdsa.ParseSignature(data.Signature[:])
			if err != nil {
				fmt.Println(err)
				return
			}

			fmt.Println(signature2)*/

		publicKey, err := btcec.ParsePubKey(data.PublicKey[:])
		if err != nil {
			fmt.Println(err)
		}

		verified := signature.Verify(messageDigest[:], publicKey)

		fmt.Println("VERIFIED", verified)

		hash160 := btcutil.Hash160(data.PublicKey[:])

		conv, err := bech32.ConvertBits(hash160, 8, 5, true)
		if err != nil {
			fmt.Println("Error:", err)
		}

		zero := make([]byte, 1)

		encoded, err := bech32.Encode("bc", append(zero, conv...))
		if err != nil {
			fmt.Println("Error:", err)
		}

		// Show the encoded data.
		fmt.Println("Encoded Data:", encoded)

		tapProtocol.currentCardNonce = data.CardNonce

	case CertificatesData:

		fmt.Println("################")
		fmt.Println("# CERTIFICATES #")
		fmt.Println("################")

		fmt.Printf("Certificate chain: %x\n", data.CertificateChain[:])

	case ErrorData:

		fmt.Println("#########")
		fmt.Println("# ERROR #")
		fmt.Println("#########")

		fmt.Println("Error: ", data.Error)
		fmt.Println("Code:  ", data.Code)

	default:

		fmt.Println("UNKNOWN TYPE", data)
	}

}
