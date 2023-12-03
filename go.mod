module github.com/schjonhaug/coinkite-tap-proto-go

go 1.19

require (
	github.com/btcsuite/btcd v0.23.4
	github.com/btcsuite/btcd/btcec/v2 v2.3.2
	github.com/btcsuite/btcd/btcutil v1.1.3
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.2.0
	github.com/ebfe/scard v0.0.0-20230420082256-7db3f9b7c8a7
	github.com/fxamacker/cbor/v2 v2.4.0
)

require github.com/pkg/errors v0.9.1 // indirect

require (
	github.com/btcsuite/btcd/chaincfg/chainhash v1.0.1 // indirect
	github.com/skythen/apdu v0.2.0
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519 // indirect
	golang.org/x/sys v0.0.0-20220722155257-8c9f86f7a55f // indirect
)
