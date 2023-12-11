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

// TAP PROTOCOL

type Satscard struct {
	ActiveSlot           int
	NumberOfSlots        int
	Identity             string
	PaymentAddress       string
	Proto                int
	Birth                int
	Version              string
	ActiveSlotPrivateKey string
	AuthDelay            int
}

type TapProtocol struct {
	appNonce             []byte
	currentCardNonce     [16]byte
	cardPublicKey        [33]byte
	sessionKey           [32]byte
	currentSlotPublicKey [33]byte
	certificateChain     [][65]byte

	cvc string

	Satscard *Satscard

	queue
}

func (tapProtocol *TapProtocol) createNonce() ([]byte, error) {

	// Create nonce
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)

	if err != nil {
		return nil, err
	}

	slog.Debug("Created nonce", "Nonce", fmt.Sprintf("%x", nonce))

	tapProtocol.appNonce = nonce

	return nonce, nil

}

func (tapProtocol *TapProtocol) ParseResponse(response []byte) ([]byte, error) {

	bytes, err := apduUnwrap(response)

	if err != nil {
		return nil, err
	}

	decMode, _ := cbor.DecOptions{ExtraReturnErrors: cbor.ExtraDecErrorUnknownField}.DecMode()

	command := tapProtocol.queue.dequeue()

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

		err = tapProtocol.parseStatusData(v)

	case "read":

		var v readData

		if err := decMode.Unmarshal(bytes, &v); err != nil {

			var e errorData

			if err := decMode.Unmarshal(bytes, &e); err != nil {
				return nil, err
			}

			return nil, fmt.Errorf("%d: %v", e.Code, e.Error)

		}

		err = tapProtocol.parseReadData(v)
	case "unseal":

		var v unsealData

		if err := decMode.Unmarshal(bytes, &v); err != nil {

			var e errorData

			if err := decMode.Unmarshal(bytes, &e); err != nil {
				return nil, err
			}

			return nil, fmt.Errorf("%d: %v", e.Code, e.Error)

		}

		err = tapProtocol.parseUnsealData(v)
	case "certs":

		var v certsData

		if err := decMode.Unmarshal(bytes, &v); err != nil {

			var e errorData

			if err := decMode.Unmarshal(bytes, &e); err != nil {
				return nil, err
			}

			return nil, fmt.Errorf("%d: %v", e.Code, e.Error)

		}

		err = tapProtocol.parseCertsData(v)
	case "check":

		var v checkData

		if err := decMode.Unmarshal(bytes, &v); err != nil {

			var e errorData

			if err := decMode.Unmarshal(bytes, &e); err != nil {
				return nil, err
			}

			return nil, fmt.Errorf("%d: %v", e.Code, e.Error)

		}

		err = tapProtocol.parseCheckData(v)
	case "new":

		var v newData

		if err := decMode.Unmarshal(bytes, &v); err != nil {

			var e errorData

			if err := decMode.Unmarshal(bytes, &e); err != nil {
				return nil, err
			}

			return nil, fmt.Errorf("%d: %v", e.Code, e.Error)

		}

		err = tapProtocol.parseNewData(v)
	case "wait":

		var v waitData

		if err := decMode.Unmarshal(bytes, &v); err != nil {

			var e errorData

			if err := decMode.Unmarshal(bytes, &e); err != nil {
				return nil, err
			}

			return nil, fmt.Errorf("%d: %v", e.Code, e.Error)

		}

		err = tapProtocol.parseWaitData(v)

	default:

		return nil, errors.New("incorrect command found in queue")

	}

	if err != nil {
		return nil, err

	}

	// Check if there are more commands to run

	return tapProtocol.nextCommand()

}

func (tapProtocol *TapProtocol) nextCommand() ([]byte, error) {

	command := tapProtocol.queue.peek()

	if command == nil {

		tapProtocol.cvc = ""

		return nil, nil
	}

	switch command {

	case "status":
		return tapProtocol.statusRequest()
	case "read":
		return tapProtocol.readRequest()
	case "unseal":
		return tapProtocol.unsealRequest()
	case "certs":
		return tapProtocol.certsRequest()
	case "check":
		return tapProtocol.checkRequest()
	case "new":
		return tapProtocol.newRequest()
	case "wait":
		return tapProtocol.waitRequest()

	default:
		return nil, errors.New("incorrect command")

	}

}

func (TapProtocol *TapProtocol) EnableDebugLogging() {

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(handler))
}

func (TapProtocol *TapProtocol) UseEmulator() {

	factoryRootPublicKeyString = "022b6750a0c09f632df32afc5bef66568667e04b2e0f57cb8640ac5a040179442b"

}
