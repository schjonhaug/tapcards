// package tapprotocol
package tapprotocol

// DATA

type CardResponse struct {
	CardNonce [16]byte `cbor:"card_nonce"`
}

type StatusData struct {
	CardResponse
	Proto     int
	Birth     int
	Slots     []int
	Address   string   `cbor:"addr"`
	Version   string   `cbor:"ver"`
	PublicKey [33]byte `cbor:"pubkey"`
}

type UnsealData struct {
	CardResponse
	Slot            int      // slot just unsealed
	PrivateKey      [32]byte `cbor:"privkey"`    // private key for spending
	PublicKey       [33]byte `cbor:"pubkey"`     // slot's pubkey (convenience, since could be calc'd from privkey)
	MasterPublicKey [32]byte `cbor:"master_pk"`  // card's master private key
	ChainCode       [32]byte `cbor:"chain_code"` // nonce provided by customer

}

type NewData struct {
	CardResponse
	Slot int
}

type readData struct {
	CardResponse
	Signature [64]byte `cbor:"sig"`    //  signature over a bunch of fields using private key of slot
	PublicKey [33]byte `cbor:"pubkey"` // public key for this slot/derivation

}

type CertificatesData struct {
	CertificateChain [][65]byte `cbor:"cert_chain"`
}

type ErrorData struct {
	Code  int
	Error string
}
