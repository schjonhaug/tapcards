package main

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
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
	Proto     int
	Birth     int
	Slots     []int
	Addr      string
	Ver       string
	Pubkey    []byte
	CardNonce []byte `cbor:"card_nonce"`
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
	/*fmt.Printf("cardResponse: %+v\n", cardResponse)
	fmt.Printf("ADDR: %+v\n", cardResponse.Addr)
	fmt.Printf("PubKey: %+v\n", cardResponse.Pubkey)
	fmt.Printf("Pubkey: %+v\n", string(cardResponse.Pubkey[:]))
	fmt.Printf("CardNonce: %+v\n", cardResponse.CardNonce)
	fmt.Printf("CardNonce: %+v\n", string(cardResponse.CardNonce[:]))
	fmt.Printf("xSlots: %+v\n", cardResponse.Slots)

	print(cardPubkeyToIdent(cardResponse.Pubkey))*/

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

func (tapProtocol TapProtocol) Authenticate(cvc string, command string) (ephemeralPublicKey, xcvc []byte) {

	ephemeralPrivateKey, err := btcec.NewPrivateKey()
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
	ephemeralPublicKey = ephemeralPrivateKey.PubKey().SerializeCompressed()

	cardPubKey, err := btcec.ParsePubKey(tapProtocol.Pubkey)
	if err != nil {
		fmt.Println(err)
		panic(err)
	}
	sessionKey := btcec.GenerateSharedSecret(ephemeralPrivateKey, cardPubKey)

	fmt.Printf("Session Key: %+v\n", hex.EncodeToString(sessionKey))

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
	Slot int
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
