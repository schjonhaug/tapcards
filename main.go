package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/fxamacker/cbor/v2"
)

type Transport struct {
	EphemeralPubKey []byte
	XCVC            []byte
}

// DATA

type CardResponse struct {
	CardNonce [16]byte `cbor:"card_nonce"`
}

type StatusData struct {
	CardResponse
	Proto     int
	Birth     int
	Slots     []int
	Address   string   `cbor:"addr"`
	Version   string   `cbor:"ver"`
	PublicKey [33]byte `cbor:"pubkey"`
}

type UnsealData struct {
	CardResponse
	Slot            int      // slot just unsealed
	PrivateKey      [32]byte `cbor:"privkey"`    // private key for spending
	PublicKey       [33]byte `cbor:"pubkey"`     // slot's pubkey (convenience, since could be calc'd from privkey)
	MasterPublicKey [32]byte `cbor:"master_pk"`  // card's master private key
	ChainCode       [32]byte `cbor:"chain_code"` // nonce provided by customer

}

type NewData struct {
	CardResponse
	Slot int
}

type ReadData struct {
	CardResponse
	Signature [64]byte `cbor:"sig"`    //  signature over a bunch of fields using private key of slot
	PublicKey [33]byte `cbor:"pubkey"` // public key for this slot/derivation

}

type ErrorData struct {
	Code  int
	Error string
}

func (transport *Transport) reader(r io.Reader, command any, channel chan any) {
	buf := make([]byte, 1024)
	_, err := r.Read(buf[:])

	if err != nil {
		print(err)
		return
	}

	decMode, _ := cbor.DecOptions{ExtraReturnErrors: cbor.ExtraDecErrorUnknownField}.DecMode()

	switch command.(type) {
	case StatusCommand:

		var v StatusData

		if err := decMode.Unmarshal(buf, &v); err != nil {
			panic(err)
		}

		channel <- v

	case UnsealCommand:

		var v UnsealData

		if err := decMode.Unmarshal(buf, &v); err != nil {

			var e ErrorData

			if err := decMode.Unmarshal(buf, &e); err != nil {
				panic(err)
			}

			channel <- e

		}

		channel <- v
	case NewCommand:

		var v NewData

		if err := decMode.Unmarshal(buf, &v); err != nil {

			var e ErrorData

			if err := decMode.Unmarshal(buf, &e); err != nil {
				panic(err)
			}

			channel <- e

		}

		channel <- v
	case ReadCommand:

		var v ReadData

		if err := decMode.Unmarshal(buf, &v); err != nil {

			var e ErrorData

			if err := decMode.Unmarshal(buf, &e); err != nil {
				panic(err)
			}

			channel <- e

		}

		channel <- v

	default:

		var v ErrorData

		if err := decMode.Unmarshal(buf, &v); err != nil {
			panic(err)
		}

		channel <- v

		fmt.Println("Unknown command??")
	}

}

func (transport Transport) Send(command any, channel chan any) {

	cbor_serialized, err := cbor.Marshal(command)
	if err != nil {
		fmt.Println("error:", err)
	}

	connection, err := net.Dial("unix", "/tmp/ecard-pipe")
	if err != nil {
		log.Fatal(err)
	}
	defer connection.Close()

	go transport.reader(connection, command, channel)
	_, err = connection.Write(cbor_serialized)

	if err != nil {
		log.Fatal("write error:", err)
	}

	time.Sleep(100 * time.Millisecond)

}

// TAP PROTOCOL

type TapProtocol struct {
	CurrentCardNonce [16]byte
	CardPublicKey    [33]byte
	SessionKey       []byte
	ActiveSlot       int
	NumberOfSlots    int
}

func (tapProtocol *TapProtocol) getStatus() {

}

func (tapProtocol TapProtocol) Identity() string {
	// convert pubkey into a hash formatted for humans
	// - sha256(compressed-pubkey)
	// - skip first 8 bytes of that (because that's revealed in NFC URL)
	// - base32 and take first 20 chars in 4 groups of five
	// - insert dashes
	// - result is 23 chars long

	if len(tapProtocol.CardPublicKey) != 33 {
		panic("expecting compressed pubkey")
	}

	checksum := sha256.Sum256(tapProtocol.CardPublicKey[:])

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

// GenerateSharedSecret generates a shared secret based on a private key and a
// public key using Diffie-Hellman key exchange (ECDH) (RFC 5903).
// RFC5903 Section 9 states we should only return x.
//
// It is recommended to securily hash the result before using as a cryptographic
// key.
func GenerateSharedSecret(privateKey *secp256k1.PrivateKey, publicKey *secp256k1.PublicKey) []byte {

	var point, result secp256k1.JacobianPoint
	publicKey.AsJacobian(&point)
	secp256k1.ScalarMultNonConst(&privateKey.Key, &point, &result)
	result.ToAffine()
	xBytes := result.X.Bytes()

	fmt.Println("Y:", publicKey.Y().Text(2))
	// Get the last digit of the big integer
	//lastDigit := new(big.Int).Mod(publicKey.Y(), big.NewInt(10))
	//fmt.Println("last digit:", lastDigit.Text(2))

	y := new(big.Int)
	y.SetBytes(result.Y.Bytes()[:])

	// Perform a bitwise AND with 0x01
	andResult := new(big.Int).And(y, big.NewInt(0x01))
	fmt.Println("and Result:", andResult.Text(2))

	// Perform a bitwise OR with 0x02
	orResult := new(big.Int).Or(andResult, big.NewInt(0x02))

	fmt.Println("orResult:", orResult.Text(2))

	even := orResult.Bytes()

	sharedSecret := append(even, xBytes[:]...)

	println(len(sharedSecret))

	return sharedSecret
}

func (tapProtocol TapProtocol) Authenticate(cvc string, command Command) (*Auth, error) {

	fmt.Println("\n########")
	fmt.Println("# AUTH #")
	fmt.Println("########")

	fmt.Println("CVC:", cvc)
	fmt.Println("Command:", command.Cmd)

	cardPublicKey, err := secp256k1.ParsePubKey(tapProtocol.CardPublicKey[:])
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
	sessionKey := sha256.Sum256(GenerateSharedSecret(ephemeralPrivateKey, cardPublicKey))

	fmt.Printf("Session Key:  %x\n", sessionKey)
	fmt.Printf("CurrentCardNonce:  %x\n", tapProtocol.CurrentCardNonce)

	md := sha256.Sum256(append(tapProtocol.CurrentCardNonce[:], []byte(command.Cmd)...))

	mask := xor(sessionKey[:], md[:])[:len(cvc)]

	xcvc := xor([]byte(cvc), mask)

	fmt.Printf("xcvc %x\n", xcvc)

	auth := Auth{EphemeralPubKey: ephemeralPublicKey, XCVC: xcvc}

	return &auth, nil

}

// COMMANDS

type Command struct {
	Cmd string `cbor:"cmd"`
}

type Auth struct {
	EphemeralPubKey []byte `cbor:"epubkey"` //app's ephemeral public key
	XCVC            []byte `cbor:"xcvc"`    //encrypted CVC value
}

type StatusCommand struct {
	Command
}

type UnsealCommand struct {
	Command
	Auth
	Slot int `cbor:"slot"`
}

type NewCommand struct {
	Command
	Auth
	Slot int `cbor:"slot"` // (optional: default zero) slot to be affected, must equal currently-active slot number
	//ChainCode [32]byte `cbor:"chain_code"` // app's entropy share to be applied to new slot (optional on SATSCARD)

}

type ReadCommand struct {
	Command
	Auth
	Nonce []byte `cbor:"nonce"` // provided by app, cannot be all same byte (& should be random)
}

//

func sendReceive(command any) {

	channel := make(chan any)

	var transport Transport

	go transport.Send(command, channel)

	data := <-channel

	// Get the nonce and save it.

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

		tapProtocol.CardPublicKey = data.PublicKey
		tapProtocol.CurrentCardNonce = data.CardNonce
		tapProtocol.ActiveSlot = data.Slots[0]
		tapProtocol.NumberOfSlots = data.Slots[1]

		fmt.Println("Card identity: ", tapProtocol.Identity())

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

		tapProtocol.CurrentCardNonce = data.CardNonce
		// Increase active slot

		if tapProtocol.ActiveSlot < tapProtocol.NumberOfSlots {
			tapProtocol.ActiveSlot++
		}

	case NewData:

		fmt.Println("#######")
		fmt.Println("# NEW #")
		fmt.Println("#######")

		fmt.Println("Slot:             ", data.Slot)

		tapProtocol.CurrentCardNonce = data.CardNonce

	case ReadData:

		fmt.Println("########")
		fmt.Println("# READ #")
		fmt.Println("########")

		fmt.Printf("Signature: %x\n", data.Signature)
		fmt.Printf("Public Key: %x\n", data.PublicKey)

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

		tapProtocol.CurrentCardNonce = data.CardNonce

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

var tapProtocol TapProtocol

func init() {
	print("ASDAS")

	//tapProtocol = TapProtocol{}
}

func main() {

	// STATUS

	statusCommand := StatusCommand{
		Command{Cmd: "status"},
	}

	sendReceive(statusCommand)

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
	if err != nil {
		log.Fatalf("error while generating random string: %s", err)
	}

	readCommand := ReadCommand{
		Command: command,
		Auth:    *auth,
		Nonce:   nonce,
	}

	sendReceive(readCommand)

	return

	// UNSEAL
	command = Command{Cmd: "unseal"}

	auth, err = tapProtocol.Authenticate("123456", command)

	if err != nil {
		fmt.Println(err)
		return
	}

	unsealCommand := UnsealCommand{
		Command: command,
		Auth:    *auth,
		Slot:    tapProtocol.ActiveSlot,
	}

	sendReceive(unsealCommand)

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
}
