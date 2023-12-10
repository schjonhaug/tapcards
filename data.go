package tapcards

// DATA

type cardResponse struct {
	CardNonce [16]byte `cbor:"card_nonce"`
}

type StatusData struct {
	cardResponse
	Proto     int
	Birth     int
	Slots     []int
	Address   string   `cbor:"addr"`
	Version   string   `cbor:"ver"`
	PublicKey [33]byte `cbor:"pubkey"`
	AuthDelay int      `cbor:"auth_delay"`
}

type unsealData struct {
	cardResponse
	Slot            int      // slot just unsealed
	PrivateKey      [32]byte `cbor:"privkey"`    // private key for spending
	PublicKey       [33]byte `cbor:"pubkey"`     // slot's pubkey (convenience, since could be calc'd from privkey)
	MasterPublicKey [32]byte `cbor:"master_pk"`  // card's master private key
	ChainCode       [32]byte `cbor:"chain_code"` // nonce provided by customer

}

type newData struct {
	cardResponse
	Slot int
}

type checkData struct {
	cardResponse
	AuthSignature [64]byte `cbor:"auth_sig"` //  signature using card_pubkey
}

type readData struct {
	cardResponse
	Signature [64]byte `cbor:"sig"`    //  signature over a bunch of fields using private key of slot
	PublicKey [33]byte `cbor:"pubkey"` // public key for this slot/derivation

}

type certsData struct {
	CertificateChain [][65]byte `cbor:"cert_chain"`
}

type waitData struct {
	Success   bool `cbor:"success"`
	AuthDelay int  `cbor:"auth_delay"`
}

type ErrorData struct {
	Code  int
	Error string
}
