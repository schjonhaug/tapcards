package cktap

import (
	"fmt"
	"log/slog"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

func (satscard *Satscard) UnsealRequest(cvc string) ([]byte, error) {

	slog.Debug("Request unseal")

	if satscard.currentCardNonce == [16]byte{} {
		satscard.queue.enqueue("status")
	}

	satscard.queue.enqueue("unseal")

	satscard.cvc = cvc

	return satscard.nextCommand()

}

func (satscard *Satscard) unsealRequest() ([]byte, error) {

	command := command{Cmd: "unseal"}

	auth, err := satscard.authenticate(satscard.cvc, command)

	if err != nil {
		return nil, err
	}

	unsealCommand := unsealCommand{
		command: command,
		auth:    *auth,
		Slot:    satscard.ActiveSlot,
	}

	return apduWrap(unsealCommand)

}

func (satscard *Satscard) parseUnsealData(unsealData unsealData) error {

	slog.Debug("Parse unseal")

	slog.Debug("UNSEAL", "Slot", unsealData.Slot)
	slog.Debug("UNSEAL", "PrivateKey", fmt.Sprintf("%x", unsealData.PrivateKey))
	slog.Debug("UNSEAL", "PublicKey", fmt.Sprintf("%x", unsealData.PublicKey))
	slog.Debug("UNSEAL", "MasterPublicKey", fmt.Sprintf("%x", unsealData.MasterPublicKey))
	slog.Debug("UNSEAL", "ChainCode", fmt.Sprintf("%x", unsealData.ChainCode))
	slog.Debug("UNSEAL", "CardNonce", fmt.Sprintf("%x", unsealData.CardNonce))

	satscard.currentCardNonce = unsealData.CardNonce

	// Calculate and return private key as wif

	unencryptedPrivateKeyBytes, err := xor(unsealData.PrivateKey[:], satscard.sessionKey[:])
	if err != nil {
		return err
	}

	privateKey, _ := btcec.PrivKeyFromBytes(unencryptedPrivateKeyBytes)

	// TODO support other than mainnet for development and testing purposes
	wif, err := btcutil.NewWIF(privateKey, &chaincfg.MainNetParams, true)

	if err != nil {
		return err
	}

	satscard.ActiveSlotPrivateKey = wif.String()

	return nil

}
