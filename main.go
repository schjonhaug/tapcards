package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

type Transport struct {
}

func (transport Transport) reader(r io.Reader) {
	buf := make([]byte, 1024)
	_, err := r.Read(buf[:])
	if err != nil {
		return
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

	//var status interface{}
	var status Status

	if err := cbor.Unmarshal(buf, &status); err != nil {
		panic(err)
	}
	fmt.Printf("STATUS: %+v\n", status)
	fmt.Printf("ADDR: %+v\n", status.Addr)
	fmt.Printf("PubKey: %+v\n", status.Pubkey)
	fmt.Printf("Pubkey: %+v\n", string(status.Pubkey[:]))
	fmt.Printf("CardNonce: %+v\n", status.CardNonce)
	fmt.Printf("CardNonce: %+v\n", string(status.CardNonce[:]))
	fmt.Printf("xSlots: %+v\n", status.Slots)

	print(cardPubkeyToIdent(status.Pubkey))

	//c <- status

	//ec()

}

func (transport Transport) Send(message interface{}) {

	cbor_serialized, err := cbor.Marshal(message)
	if err != nil {
		fmt.Println("error:", err)
	}

	c, err := net.Dial("unix", "/tmp/ecard-pipe")
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
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
	go transport.reader(c)
	_, err = c.Write(cbor_serialized)

	if err != nil {
		log.Fatal("write error:", err)
	}
	//transport.reader(c)
	time.Sleep(100 * time.Millisecond)

}

type TapProtocol struct {
	pubKey []byte
}

func Status(tapProtocol TapProtocol) {

}

func cardPubkeyToIdent(cardPubkey []byte) string {
	// convert pubkey into a hash formated for humans
	// - sha256(compressed-pubkey)
	// - skip first 8 bytes of that (because that's revealed in NFC URL)
	// - base32 and take first 20 chars in 4 groups of five
	// - insert dashes
	// - result is 23 chars long

	if len(cardPubkey) != 33 {
		panic("expecting compressed pubkey")
	}

	checksum := sha256.Sum256(cardPubkey[8:])

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

func ec() {

	/*

			Next, we call ecdsa.GenerateKey with elliptic.P256() as the first argument, which represents the secp256k1 curve. The second argument is a rand.Reader, which provides a source of cryptographically secure random data for generating the private key.

		Finally, we print the private key, along with the corresponding public key coordinates X and Y.

	*/

	// Create a new private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Print("\n")
	fmt.Printf("Private Key: %x\n", privateKey.D.Bytes())
	fmt.Printf("Public Key X: %x\n", privateKey.PublicKey.X.Bytes())
	fmt.Printf("Public Key Y: %x\n", privateKey.PublicKey.Y.Bytes())

	// Use the P256 curve (secp256k1)
	curve := elliptic.P256()

	// Choose two random points on the curve
	//x1, y1 := curve.ScalarBaseMult([]byte{1, 2, 3, 4, 5})
	//x2, y2 := curve.ScalarBaseMult([]byte{6, 7, 8, 9, 10})
	x1, y1 := curve.ScalarBaseMult(privateKey.PublicKey.X.Bytes())
	x2, y2 := curve.ScalarBaseMult(privateKey.PublicKey.X.Bytes())

	// Perform point addition to get a third point on the curve
	x3, y3 := curve.Add(x1, y1, x2, y2)

	fmt.Printf("Point 1 X: %x\n", x1.Bytes())
	fmt.Printf("Point 1 Y: %x\n", y1.Bytes())
	fmt.Printf("Point 2 X: %x\n", x2.Bytes())
	fmt.Printf("Point 2 Y: %x\n", y2.Bytes())
	fmt.Printf("Point 3 X: %x\n", x3.Bytes())
	fmt.Printf("Point 3 Y: %x\n", y3.Bytes())

}

func main() {

	app_id, err := hex.DecodeString("f0436f696e6b697465434152447631")
	if err != nil {
		panic(err)
	}
	fmt.Printf("% x\n", app_id)

	type Command struct {
		Cmd string `json:"cmd"`
	}
	status := Command{Cmd: "status"}

	var transport Transport
	transport.Send(status)

	/*
	   fmt.Printf("%+v\n", status)

	   var buffer bytes.Buffer        // Stand-in for a buffer connection
	   enc := gob.NewEncoder(&buffer) // Will write to buffer.

	   err = enc.Encode(status)

	   	if err != nil {
	   		log.Fatal("encode error:", err)
	   	}

	   // HERE ARE YOUR BYTES!!!!
	   //fmt.Println(buffer.Bytes())

	   json_serialized, err := json.Marshal(status)

	   	if err != nil {
	   		fmt.Println(err)
	   		return
	   	}

	   fmt.Println(string(json_serialized))

	   cbor_serialized, err := cbor.Marshal(status)

	   	if err != nil {
	   		fmt.Println("error:", err)
	   	}

	   fmt.Println(string(cbor_serialized))
	   //capdu := apdu.Capdu{Cla: 0x00, Ins: 0xa4, P1: 4, Data: buffer.Bytes()}
	   capdu := apdu.Capdu{Cla: 0x01, Ins: 0x01, Data: cbor_serialized}

	   fmt.Println(capdu)

	   cbor_capdu_serialized, err := cbor.Marshal(capdu)

	   	if err != nil {
	   		fmt.Println("error:", err)
	   	}

	   fmt.Printf("cbor_capdu_serialized %x\n", cbor_capdu_serialized)

	   capdu_bytes, err := capdu.Bytes()

	   	if err != nil {
	   		fmt.Println("error:", err)
	   	}

	   fmt.Printf("capdu_bytes %x\n", capdu_bytes)
	*/
}
