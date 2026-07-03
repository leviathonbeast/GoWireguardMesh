package main

import (
	//	"crypto/ecdsa"
	//	"crypto/elliptic"
	//	"crypto/rand"
	"fmt"
	"log"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	// "golang.zx2c4.com/wireguard/wgctrl"
)

func main() {
	//curve := elliptic.P256()
	//privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		log.Fatalf("generate private key: %v", err)
	}
	publicKey := privateKey.PublicKey()

	fmt.Println("curve25519 Key Pair Generated Successfully")

	fmt.Printf("Public Key: %s\n", publicKey)
	fmt.Printf("Private Key %s\n", privateKey)

}
