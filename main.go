package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
)

const (
	keySize   = 32
	chunkSize = 1024 * 1024 // 1 MB

	// AAD (Additional authenticated data) is to be used in the GCM algorithm
	AAD = "7f57c07ee9459ed704d5e403086f6503"
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
	if err != nil || len(key) != keySize {
		logger.Fatalf("Invalid key. Must be a valid %d byte hex encoded string\n", keySize)
	}
	iv, err := hex.DecodeString(ivString)
	if err != nil {
		logger.Fatalln("Invalid IV. Must be a valid hex encoded string")
	}
	aad, err := hex.DecodeString(AAD)
	if err != nil {
		panic(err)
	}
	if encrypt {
		err = encryptFile(inputPath, outputPath, key, iv, aad)
	} else if decrypt {
		err = decryptFile(inputPath, outputPath, key, iv, aad)
	}
	if err != nil {
		log.Fatalln(err.Error())
	}
}

func encryptFile(inFilePath, outFilePath string, key, iv, aad []byte) error {
	if _, err := os.Stat(inFilePath); os.IsNotExist(err) {
		return fmt.Errorf("A file does not exist at %s", inFilePath)
	}

	inFile, err := os.Open(inFilePath)
	if err != nil {
		return err
	}
	defer inFile.Close()

	outFile, err := os.OpenFile(outFilePath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer outFile.Close()

	aes, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCMWithNonceSize(aes, len(iv))
	if err != nil {
		return err
	}

	chunk := make([]byte, chunkSize)
	for {
		eof := false
		read, err := inFile.Read(chunk)
		if err == io.EOF {
			eof = true
		} else if err != nil {
			return err
		}
		encrChunk := gcm.Seal(nil, iv, chunk[:read], aad)
		outFile.Write(encrChunk)
		if read < chunkSize || eof {
			break
		}
		incrementIV(iv)
	}
	return nil
}

func decryptFile(inFilePath, outFilePath string, key, iv, aad []byte) error {
	if _, err := os.Stat(inFilePath); os.IsNotExist(err) {
		return fmt.Errorf("A file does not exist at %s", inFilePath)
	}

	inFile, err := os.Open(inFilePath)
	if err != nil {
		return err
	}
	defer inFile.Close()

	outFile, err := os.OpenFile(outFilePath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer outFile.Close()

	aes, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCMWithNonceSize(aes, len(iv))
	if err != nil {
		return err
	}

	chunk := make([]byte, chunkSize+gcm.Overhead())
	for {
		eof := false
		read, err := inFile.Read(chunk)
		if err == io.EOF {
			eof = true
		} else if err != nil {
			return err
		}
		decrChunk, err := gcm.Open(nil, iv, chunk[:read], aad)
		if err != nil {
			return err
		}
		outFile.Write(decrChunk)
		if read < chunkSize || eof {
			break
		}
		incrementIV(iv)
	}
	return nil
}

func incrementIV(iv []byte) {
	for i := len(iv) - 1; i >= 0; i-- {
		iv[i]++
		if iv[i] != 0 {
			return
		}
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
