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

type Satscard struct {

	// Public

	ActiveSlot           int
	NumberOfSlots        int
	Identity             string
	PaymentAddress       string
	Proto                int
	Birth                int
	Version              string
	ActiveSlotPrivateKey string
	AuthDelay            int

	// Private

	appNonce             []byte
	currentCardNonce     [16]byte
	cardPublicKey        [33]byte
	sessionKey           [32]byte
	currentSlotPublicKey [33]byte
	certificateChain     [][65]byte

	cvc string

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

func (satscard *Satscard) EnableDebugLogging() {

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(handler))
}

func (satscard *Satscard) UseEmulator() {

	factoryRootPublicKeyString = "022b6750a0c09f632df32afc5bef66568667e04b2e0f57cb8640ac5a040179442b"

}
