package main

import (
	"encoding/hex"
	"flag"
	"log"
	"os"

	"github.com/catalyzeio/gcm/gcm"
)

const (
	keySize   = 32
	minIVSize = 12
)

var (
	logger = log.New(os.Stderr, "GCM ", log.LstdFlags)

	encrypt    bool
	decrypt    bool
	keyString  string
	ivString   string
	inputPath  string
	outputPath string
)

func main() {
	flag.BoolVar(&encrypt, "e", false, "Enrypt the given file")
	flag.BoolVar(&decrypt, "d", false, "Decrypt the given file")
	flag.StringVar(&keyString, "K", "", "The hex encoded key")
	flag.StringVar(&ivString, "iv", "", "The hex encoded IV")
	flag.StringVar(&inputPath, "in", "", "The input file")
	flag.StringVar(&outputPath, "out", "", "The output file")
	flag.Parse()
	checkRequiredFlags()
	key, err := hex.DecodeString(keyString)
	if err != nil {
		logger.Fatalf("Invalid key: %s.", err)
	}
	if len(key) != keySize {
		logger.Fatalf("Invalid key. Must be a valid hex encoded string at least %d bytes long.", keySize)
	}
	iv, err := hex.DecodeString(ivString)
	if err != nil {
		logger.Fatalf("Invalid IV: %s.", err)
	}
	if len(iv) < minIVSize {
		logger.Fatalf("Invalid IV. Must be a valid hex encoded string at least %d bytes long.", minIVSize)
	}
	aad, err := hex.DecodeString(gcm.AAD)
	if err != nil {
		panic(err)
	}
	if encrypt {
		err = gcm.EncryptFile(inputPath, outputPath, key, iv, aad)
	} else if decrypt {
		err = gcm.DecryptFile(inputPath, outputPath, key, iv, aad)
	}
	if err != nil {
		log.Fatalln(err.Error())
	}
}

func checkRequiredFlags() {
	if (encrypt && decrypt) || (!encrypt && !decrypt) {
		logger.Fatalln("-e or -d must be specified, but not both")
	}
	if keyString == "" {
		logger.Fatalln("-K is required")
	}
	if ivString == "" {
		logger.Fatalln("-iv is required")
	}
	if inputPath == "" {
		logger.Fatalln("-in is required")
	}
	if outputPath == "" {
		logger.Fatalln("-out is required")
	}
}
