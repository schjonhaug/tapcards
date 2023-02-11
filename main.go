package main

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/fxamacker/cbor/v2"
)

type Transport struct {
	EphemeralPubKey []byte
	XCVC            []byte
}

type CardResponse struct {
	CardNonce []byte `cbor:"card_nonce"`
}

type Status struct {
	CardResponse
	Proto  int
	Birth  int
	Slots  []int
	Addr   string
	Ver    string
	Pubkey []byte

	//CardNonce []byte `cbor:"card_nonce"`
}

func (transport Transport) reader(r io.Reader, channel chan Status) {
	buf := make([]byte, 1024)
	_, err := r.Read(buf[:])
	if err != nil {
		return
	}

	//var status Status
	var i Status

	if err := cbor.Unmarshal(buf, &i); err != nil {
		panic(err)
	}

	channel <- i

}

func (transport Transport) Send(message interface{}, channel chan Status) {

	cbor_serialized, err := cbor.Marshal(message)
	if err != nil {
		fmt.Println("error:", err)
	}

	connection, err := net.Dial("unix", "/tmp/ecard-pipe")
	if err != nil {
		log.Fatal(err)
	}
	defer connection.Close()
	/*
		cls := 0x00
		ins := 0xCB
		p1 := 0x00
		p2 := 0x00

		//standard format
		result := make([]byte, 0, 30000)
		result = append(result, []byte{cls, ins, p1, p2, byte(len(json_serialized))}...)
		result = append(result, c.json_serialized...)

		//apdu := {cls, ins, 0, 0, len(json_serialized), json_serialized}
	*/
	go transport.reader(connection, channel)
	_, err = connection.Write(cbor_serialized)

	if err != nil {
		log.Fatal("write error:", err)
	}
	//transport.reader(c)
	time.Sleep(100 * time.Millisecond)

}

type TapProtocol struct {
	CurrentCardNonce []byte
	Pubkey           []byte
}

/*func Status(tapProtocol TapProtocol) {

}*/

func (tapProtocol TapProtocol) Identity() string {
	// convert pubkey into a hash formated for humans
	// - sha256(compressed-pubkey)
	// - skip first 8 bytes of that (because that's revealed in NFC URL)
	// - base32 and take first 20 chars in 4 groups of five
	// - insert dashes
	// - result is 23 chars long

	if len(tapProtocol.Pubkey) != 33 {
		panic("expecting compressed pubkey")
	}

	checksum := sha256.Sum256(tapProtocol.Pubkey[8:])

	base32String := base32.StdEncoding.EncodeToString(checksum[:])

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

	// Get the last digit of the big integer
	lastDigit := new(big.Int).Mod(publicKey.X(), big.NewInt(10))

	// Perform a bitwise AND with 0x01
	andResult := new(big.Int).And(lastDigit, big.NewInt(0x01))

	// Perform a bitwise OR with 0x02
	orResult := new(big.Int).Or(andResult, big.NewInt(0x02))

	fmt.Println("x:", publicKey.X().Text(2))
	fmt.Println("orResult:", orResult.Text(2))

	even := orResult.Bytes()

	sharedSecret := append(even, xBytes[:]...)

	println(len(sharedSecret))

	return sharedSecret
}

func (tapProtocol TapProtocol) Authenticate(cvc string, command string) (ephemeralPublicKey, xcvc []byte) {

	//privA, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	//pubA := privA.PublicKey

	cardPubKey, err := secp256k1.ParsePubKey(tapProtocol.Pubkey)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}

	fmt.Printf("\ncardPubKey:  %x\n", cardPubKey.SerializeCompressed())

	// Derive an ephemeral public/private keypair for performing ECDHE with
	// the recipient.
	ephemeralPrivateKey, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		fmt.Println(err)
		return
	}
	ephemeralPublicKey = ephemeralPrivateKey.PubKey().SerializeCompressed()

	// Using ECDHE, derive a shared symmetric key for encryption of the plaintext.
	sessionKey := sha256.Sum256(GenerateSharedSecret(ephemeralPrivateKey, cardPubKey))

	fmt.Printf("Session Key:  %x\n", sessionKey)

	md := sha256.Sum256(append(tapProtocol.CurrentCardNonce, []byte(command)...))

	mask := xor(sessionKey[:], md[:])[:len(cvc)]

	xcvc = xor([]byte(cvc), mask)

	return

}

type Command struct {
	Cmd string `cbor:"cmd"`
}

type Auth struct {
	EphemeralPubKey []byte `cbor:"epubkey"` //app's ephemeral public key
	XCVC            []byte `cbor:"xcvc"`    //encrypted CVC value
}

type Unseal struct {
	Command
	Auth
	Slot int `cbor:"slot"`
}

func main() {

	command := Command{Cmd: "status"}

	channel := make(chan Status)

	var transport Transport

	go transport.Send(command, channel)

	i := <-channel

	fmt.Print("\nINTERFACE\n")
	fmt.Printf("\n%+v\n", i)

	var tapProtocol TapProtocol

	tapProtocol.Pubkey = i.Pubkey
	tapProtocol.CurrentCardNonce = i.CardNonce

	fmt.Printf("Pubkey    %+v\n", hex.EncodeToString(i.Pubkey))
	fmt.Printf("CardNonce %+v\n", hex.EncodeToString(i.CardNonce))

	fmt.Print("\n")
	fmt.Print(tapProtocol.Identity())
	fmt.Print("\n")

	fmt.Print("\n")
	ephemeralPublicKey, xcvc := tapProtocol.Authenticate("123456", "unseal")
	fmt.Print("\n")
	fmt.Printf("ephemeralPublicKey %+v\n", hex.EncodeToString(ephemeralPublicKey))
	fmt.Printf("xcvc %+v\n", hex.EncodeToString(xcvc))

	auth := Auth{EphemeralPubKey: ephemeralPublicKey, XCVC: xcvc}

	unsealCommand := Unseal{Command: Command{Cmd: "unseal"}, Auth: auth, Slot: 0}

	transport.Send(unsealCommand, channel)

}
