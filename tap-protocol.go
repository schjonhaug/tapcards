package tapprotocol

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// TAP PROTOCOL

type TapProtocol struct {
	nonce                []byte
	currentCardNonce     [16]byte
	cardPublicKey        [33]byte
	sessionKey           [32]byte
	activeSlot           int
	numberOfSlots        int
	transport            Transport
	currentSlotPublicKey [33]byte
}

// Active slot number
func (tapProtocol *TapProtocol) ActiveSlot() int {
	return tapProtocol.activeSlot
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

// STATUS
func (tapProtocol *TapProtocol) Status() error {

	tapProtocol.transport.Connect()
	defer tapProtocol.transport.Disconnect()

	return tapProtocol.status()

}

func (tapProtocol *TapProtocol) status() error {

	fmt.Println("----------------------------")
	fmt.Println("Status")
	fmt.Println("----------------------------")

	statusCommand := statusCommand{command{Cmd: "status"}}

	_, error := tapProtocol.sendReceive(statusCommand)

	return error

}

func (tapProtocol *TapProtocol) Unseal(cvc string) (string, error) {

	fmt.Println("----------------------------")
	fmt.Println("Unseal")
	fmt.Println("----------------------------")

	command := command{Cmd: "unseal"}

	auth, err := tapProtocol.authenticate(cvc, command)

	if err != nil {
		fmt.Println(err)
		return "", err
	}

	unsealCommand := unsealCommand{
		command: command,
		auth:    *auth,
		Slot:    tapProtocol.activeSlot,
	}

	data, err := tapProtocol.sendReceive(unsealCommand)

	if err != nil {
		return "", err
	}

	switch data := data.(type) {
	case string:

		return data, nil
	case ErrorData:
		fmt.Println("FOUND ERROR DATA")
		return "", errors.New(data.Error)

	default:
		return "", errors.New("undefined error")

	}

}

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

	nonce, err := tapProtocol.createNonce()

	if err != nil {
		return err
	}

	switch data := data.(type) {
	case certificatesData:

		fmt.Println()
		fmt.Println("#########")
		fmt.Println("# CERTS #")
		fmt.Println("#########")

		fmt.Printf("Certificate chain: %x\n", data.CertificateChain[:])

		firstSignature := data.CertificateChain[0]

		r := new(btcec.ModNScalar)
		r.SetByteSlice(firstSignature[0:32])

		s := new(btcec.ModNScalar)
		s.SetByteSlice(firstSignature[32:])

		signature := ecdsa.NewSignature(r, s)

		checkCommand := checkCommand{
			command: command{Cmd: "check"},
			Nonce:   nonce,
		}

		data2, err := tapProtocol.sendReceive(checkCommand)

		if err != nil {
			return err
		}

		switch data2 := data2.(type) {

		case checkData:

			fmt.Println("#########")
			fmt.Println("# CHECK #")
			fmt.Println("#########")

			fmt.Printf("Auth signature: %x\n", data2.AuthSignature[:])
			fmt.Printf("Card Nonce: %x\n", data2.CardNonce[:])

			message := append([]byte("OPENDIME"), tapProtocol.currentCardNonce[:]...)
			message = append(message, data2.CardNonce[:]...)
			message = append(message, tapProtocol.currentSlotPublicKey[:]...)

			messageDigest := sha256.Sum256([]byte(message))

			fmt.Println(messageDigest)

			publicKey, err := btcec.ParsePubKey(tapProtocol.currentSlotPublicKey[:])
			if err != nil {
				return err
			}

			verified := signature.Verify(messageDigest[:], publicKey)

			if !verified {
				return errors.New("invalid signature")
			}

			tapProtocol.currentCardNonce = data2.CardNonce

		}

		return nil
	case ErrorData:
		fmt.Println("FOUND ERROR DATA")
		return errors.New(data.Error)

	default:
		return errors.New("undefined error")

	}

	//CertificateChain [][65]byte

	//factoryRootPublicKey = "03028a0e89e70d0ec0d932053a89ab1da7d9182bdc6d2f03e706ee99517d05d9e1"

	//return nil

}

func (tapProtocol *TapProtocol) New(cvc string) (int, error) {

	tapProtocol.transport.Connect()
	defer tapProtocol.transport.Disconnect()

	return tapProtocol.new(cvc)

}

func (tapProtocol *TapProtocol) new(cvc string) (int, error) {

	fmt.Println("------------")
	fmt.Println("New")
	fmt.Println("------------")

	command := command{Cmd: "new"}

	auth, err := tapProtocol.authenticate(cvc, command)

	if err != nil {
		fmt.Println(err)
		return 0, err
	}

	newCommand := newCommand{
		command: command,
		Slot:    tapProtocol.activeSlot, //TODO check maximum
		auth:    *auth,
	}

	data, err := tapProtocol.sendReceive(newCommand)

	if err != nil {
		return 0, err
	}

	switch data := data.(type) {
	case NewData:

		fmt.Println("#######")
		fmt.Println("# NEW #")
		fmt.Println("#######")

		fmt.Println("Slot:             ", data.Slot)

		tapProtocol.currentCardNonce = data.CardNonce
		tapProtocol.activeSlot = data.Slot

		return data.Slot, nil
	case ErrorData:
		fmt.Println("FOUND ERROR DATA")
		return 0, errors.New(data.Error)

	default:
		return 0, errors.New("undefined error")

	}

}

// READ
// read a SATSCARD’s current payment address
func (tapProtocol *TapProtocol) Read() (string, error) {

	tapProtocol.transport.Connect()
	defer tapProtocol.transport.Disconnect()

	return tapProtocol.read()

}

// READ
// read a SATSCARD’s current payment address
func (tapProtocol *TapProtocol) read() (string, error) {

	fmt.Println("----------------------------")
	fmt.Println("Read current payment address")
	fmt.Println("----------------------------")

	tapProtocol.status()

	// READ

	command := command{Cmd: "read"}

	nonce, err := tapProtocol.createNonce()

	if err != nil {
		return "", err
	}

	readCommand := readCommand{
		command: command,
		Nonce:   nonce,
	}

	data, err := tapProtocol.sendReceive(readCommand)

	if err != nil {
		return "", err
	}

	switch data := data.(type) {
	case readData:

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

		r := new(btcec.ModNScalar)
		r.SetByteSlice(data.Signature[0:32])

		s := new(btcec.ModNScalar)
		s.SetByteSlice(data.Signature[32:])

		signature := ecdsa.NewSignature(r, s)

		publicKey, err := btcec.ParsePubKey(data.PublicKey[:])
		if err != nil {
			return "", err
		}

		verified := signature.Verify(messageDigest[:], publicKey)

		if !verified {
			return "", errors.New("invalid signature")
		}

		// Save the current slot public key

		tapProtocol.currentSlotPublicKey = data.PublicKey

		// Convert public key to address

		hash160 := btcutil.Hash160(data.PublicKey[:])

		convertedBits, err := bech32.ConvertBits(hash160, 8, 5, true)
		if err != nil {
			return "", err
		}

		zero := make([]byte, 1)

		encoded, err := bech32.Encode("bc", append(zero, convertedBits...))
		if err != nil {
			return "", err
		}

		// Show the encoded data.
		fmt.Println("Encoded Data:", encoded)

		tapProtocol.currentCardNonce = data.CardNonce

		return encoded, nil

	case ErrorData:
		return "", errors.New(data.Error)

	default:
		return "", errors.New("undefined error")

	}

}

func (tapProtocol *TapProtocol) authenticate(cvc string, command command) (*auth, error) {

	fmt.Println("\n########")
	fmt.Println("# AUTH #")
	fmt.Println("########")

	fmt.Println("CVC:    ", cvc)
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
	tapProtocol.sessionKey = sha256.Sum256(generateSharedSecret(ephemeralPrivateKey, cardPublicKey))

	fmt.Printf("Session Key:  %x\n", tapProtocol.sessionKey)
	fmt.Printf("CurrentCardNonce:  %x\n", tapProtocol.currentCardNonce)

	md := sha256.Sum256(append(tapProtocol.currentCardNonce[:], []byte(command.Cmd)...))

	mask := xor(tapProtocol.sessionKey[:], md[:])[:len(cvc)]

	xcvc := xor([]byte(cvc), mask)

	fmt.Printf("xcvc %x\n", xcvc)

	auth := auth{EphemeralPubKey: ephemeralPublicKey, XCVC: xcvc}

	return &auth, nil

}

// xor performs a bitwise XOR operation on two byte slices.
// It takes two byte slices, a and b, as input and returns a new byte slice, c,
// where each element of c is the result of XOR operation between the corresponding elements of a and b.
// If the input slices have different lengths, it panics.
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

func (tapProtocol *TapProtocol) createNonce() ([]byte, error) {

	// Create nonce
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)

	if err != nil {
		return nil, err
	}
	fmt.Printf("\nNONCE: %x", nonce)

	tapProtocol.nonce = nonce

	return nonce, nil

}

func (tapProtocol *TapProtocol) sendReceive(command any) (any, error) {

	channel := make(chan any)

	go tapProtocol.transport.Send(command, channel)

	data := <-channel

	switch data := data.(type) {
	case statusData:

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

		return nil, nil

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

		// Calculate and return private key as wif

		unencryptedPrivateKeyBytes := xor(data.PrivateKey[:], tapProtocol.sessionKey[:])

		privateKey, _ := btcec.PrivKeyFromBytes(unencryptedPrivateKeyBytes)

		wif, err := btcutil.NewWIF(privateKey, &chaincfg.MainNetParams, true)

		if err != nil {
			return "", err
		}

		return wif.String(), nil

	case NewData:

		return data, nil

	case readData:

		return data, nil

	case certificatesData:
		return data, nil
	case checkData:
		return data, nil

	case ErrorData:

		fmt.Println("#########")
		fmt.Println("# ERROR #")
		fmt.Println("#########")

		fmt.Println("Error: ", data.Error)
		fmt.Println("Code:  ", data.Code)

		return data, nil

	default:

		fmt.Println("UNKNOWN TYPE", data)
	}

	return nil, nil

}
