package tapcards

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/fxamacker/cbor/v2"
)

const openDime = "OPENDIME"

var factoryRootPublicKeyString = "03028a0e89e70d0ec0d932053a89ab1da7d9182bdc6d2f03e706ee99517d05d9e1"

// Satscard is a struct that represents a Satscard.
type Satscard struct {

	// Public fields

	// ActiveSlot is the currently active slot on the card, counting from 0.
	ActiveSlot int
	// NumberOfSlots is the total number of slots available on the card.
	NumberOfSlots int
	// Identity is the human readable identity of the card.
	Identity string
	// ActiveSlotPaymentAddress is the payment address associated with the currently active slot.
	ActiveSlotPaymentAddress string
	// Proto is the protocol version of the card.
	Proto int
	// Birth is the block height of the card.
	Birth int
	// Version is the version of the card.
	Version string
	// ActiveSlotPrivateKey is the private key of the currently active slot.
	ActiveSlotPrivateKey string
	// AuthDelay is the authentication delay of the card.
	AuthDelay int

	// Private fields

	// appNonce is the nonce of the application.
	appNonce []byte
	// currentCardNonce is the current nonce of the card.
	currentCardNonce [16]byte
	// cardPublicKey is the public key of the card.
	cardPublicKey [33]byte
	// sessionKey is the session key of the card.
	sessionKey [32]byte
	// activeSlotPublicKey is the public key of the currently active slot.
	activeSlotPublicKey [33]byte
	// certificateChain is the certificate chain of the card.
	certificateChain [][65]byte

	// cvc is the Card Verification Code of the card.
	cvc string

	// queue is the queue of commands to be sent to the card.
	queue
}

func (satscard *Satscard) createNonce() ([]byte, error) {

	// Create nonce
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)

	if err != nil {
		return nil, err
	}

	slog.Debug("Created nonce", "Nonce", fmt.Sprintf("%x", nonce))

	satscard.appNonce = nonce

	return nonce, nil

}

func (satscard *Satscard) ParseResponse(response []byte) ([]byte, error) {

	bytes, err := apduUnwrap(response)

	if err != nil {
		return nil, err
	}

	decMode, _ := cbor.DecOptions{ExtraReturnErrors: cbor.ExtraDecErrorUnknownField}.DecMode()

	command := satscard.queue.dequeue()

	if command == nil {
		return nil, fmt.Errorf("queue empty")
	}

	//TODO: Take a look at generics to see if we can avoid code repetition here
	switch command {
	case "status":

		var v statusData

		if err := decMode.Unmarshal(bytes, &v); err != nil {

			var e errorData

			if err := decMode.Unmarshal(bytes, &e); err != nil {

				return nil, err
			}

			return nil, fmt.Errorf("%d: %v", e.Code, e.Error)

		}

		err = satscard.parseStatusData(v)

	case "read":

		var v readData

		if err := decMode.Unmarshal(bytes, &v); err != nil {

			var e errorData

			if err := decMode.Unmarshal(bytes, &e); err != nil {
				return nil, err
			}

			return nil, fmt.Errorf("%d: %v", e.Code, e.Error)

		}

		err = satscard.parseReadData(v)
	case "unseal":

		var v unsealData

		if err := decMode.Unmarshal(bytes, &v); err != nil {

			var e errorData

			if err := decMode.Unmarshal(bytes, &e); err != nil {
				return nil, err
			}

			return nil, fmt.Errorf("%d: %v", e.Code, e.Error)

		}

		err = satscard.parseUnsealData(v)
	case "certs":

		var v certsData

		if err := decMode.Unmarshal(bytes, &v); err != nil {

			var e errorData

			if err := decMode.Unmarshal(bytes, &e); err != nil {
				return nil, err
			}

			return nil, fmt.Errorf("%d: %v", e.Code, e.Error)

		}

		err = satscard.parseCertsData(v)
	case "check":

		var v checkData

		if err := decMode.Unmarshal(bytes, &v); err != nil {

			var e errorData

			if err := decMode.Unmarshal(bytes, &e); err != nil {
				return nil, err
			}

			return nil, fmt.Errorf("%d: %v", e.Code, e.Error)

		}

		err = satscard.parseCheckData(v)
	case "new":

		var v newData

		if err := decMode.Unmarshal(bytes, &v); err != nil {

			var e errorData

			if err := decMode.Unmarshal(bytes, &e); err != nil {
				return nil, err
			}

			return nil, fmt.Errorf("%d: %v", e.Code, e.Error)

		}

		err = satscard.parseNewData(v)
	case "wait":

		var v waitData

		if err := decMode.Unmarshal(bytes, &v); err != nil {

			var e errorData

			if err := decMode.Unmarshal(bytes, &e); err != nil {
				return nil, err
			}

			return nil, fmt.Errorf("%d: %v", e.Code, e.Error)

		}

		err = satscard.parseWaitData(v)

	default:

		return nil, errors.New("incorrect command found in queue")

	}

	if err != nil {
		return nil, err

	}

	// Check if there are more commands to run

	return satscard.nextCommand()

}

func (satscard *Satscard) nextCommand() ([]byte, error) {

	command := satscard.queue.peek()

	if command == nil {

		satscard.cvc = ""

		return nil, nil
	}

	switch command {

	case "status":
		return satscard.statusRequest()
	case "read":
		return satscard.readRequest()
	case "unseal":
		return satscard.unsealRequest()
	case "certs":
		return satscard.certsRequest()
	case "check":
		return satscard.checkRequest()
	case "new":
		return satscard.newRequest()
	case "wait":
		return satscard.waitRequest()

	default:
		return nil, errors.New("incorrect command")

	}

}

// EnableDebugLogging is a function that enables debug logging in the application.
// It creates a new text handler that writes to the standard error output and sets the log level to debug.
// It then sets this handler as the default handler for the slog package.
func EnableDebugLogging() {

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(handler))
}

// UseEmulator is a function that sets the factory root public key string to the specific value associated with the emulator.
func UseEmulator() {

	factoryRootPublicKeyString = "022b6750a0c09f632df32afc5bef66568667e04b2e0f57cb8640ac5a040179442b"

}
