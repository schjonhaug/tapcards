package tapcards

import (
	"fmt"
	"log/slog"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

func (tapProtocol *TapProtocol) UnsealRequest(cvc string) ([]byte, error) {

	slog.Debug("Request unseal")

	if tapProtocol.currentCardNonce == [16]byte{} {
		tapProtocol.queue.enqueue("status")
	}

	tapProtocol.queue.enqueue("unseal")

	tapProtocol.cvc = cvc

	return tapProtocol.nextCommand()

}

func (tapProtocol *TapProtocol) unsealRequest() ([]byte, error) {

	command := command{Cmd: "unseal"}

	auth, err := tapProtocol.authenticate(tapProtocol.cvc, command)

	if err != nil {
		return nil, err
	}

	unsealCommand := unsealCommand{
		command: command,
		auth:    *auth,
		Slot:    tapProtocol.Satscard.ActiveSlot,
	}

	return apduWrap(unsealCommand)

}

func (tapProtocol *TapProtocol) parseUnsealData(unsealData unsealData) error {

	slog.Debug("Parse unseal")

	slog.Debug("UNSEAL", "Slot", unsealData.Slot)
	slog.Debug("UNSEAL", "PrivateKey", fmt.Sprintf("%x", unsealData.PrivateKey))
	slog.Debug("UNSEAL", "PublicKey", fmt.Sprintf("%x", unsealData.PublicKey))
	slog.Debug("UNSEAL", "MasterPublicKey", fmt.Sprintf("%x", unsealData.MasterPublicKey))
	slog.Debug("UNSEAL", "ChainCode", fmt.Sprintf("%x", unsealData.ChainCode))
	slog.Debug("UNSEAL", "CardNonce", fmt.Sprintf("%x", unsealData.CardNonce))

	tapProtocol.currentCardNonce = unsealData.CardNonce

	// Calculate and return private key as wif

	unencryptedPrivateKeyBytes, err := xor(unsealData.PrivateKey[:], tapProtocol.sessionKey[:])
	if err != nil {
		return err
	}

	privateKey, _ := btcec.PrivKeyFromBytes(unencryptedPrivateKeyBytes)

	// TODO support other than mainnet for development and testing purposes
	wif, err := btcutil.NewWIF(privateKey, &chaincfg.MainNetParams, true)

	if err != nil {
		return err
	}

	tapProtocol.Satscard.ActiveSlotPrivateKey = wif.String()

	return nil

}
