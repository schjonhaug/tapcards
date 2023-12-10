package tapcards

// COMMANDS

type Command struct {
	Cmd string `cbor:"cmd"`
}

type auth struct {
	EphemeralPubKey []byte `cbor:"epubkey"` //app's ephemeral public key
	XCVC            []byte `cbor:"xcvc"`    //encrypted CVC value
}

type StatusCommand struct {
	Command
}

type unsealCommand struct {
	Command
	auth
	Slot int `cbor:"slot"`
}

type newCommand struct {
	Command
	auth
	Slot int `cbor:"slot"` // (optional: default zero) slot to be affected, must equal currently-active slot number
	//ChainCode [32]byte `cbor:"chain_code"` // app's entropy share to be applied to new slot (optional on SATSCARD)

}

type readCommand struct {
	Command
	Nonce []byte `cbor:"nonce"` // provided by app, cannot be all same byte (& should be random)
}

type certsCommand struct {
	Command
}

type checkCommand struct {
	Command
	Nonce []byte `cbor:"nonce"` // provided by app, cannot be all same byte (& should be random)
}

type waitCommand struct {
	Command
}
