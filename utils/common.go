package utils

import (
	crypto "github.com/libp2p/go-libp2p/core/crypto"
)

type Identity struct {
	PeerID crypto.PrivKey `json:"id"`
	Alias  string         `json:"alias"`
	Birth  int64          `json:"birth"`
}

type Settings struct {
}
