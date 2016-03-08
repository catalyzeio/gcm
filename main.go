package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
)

const (
	keySize   = 32
	chunkSize = 1024 * 1024 // 1 MB
)

var (
	logger = log.New(os.Stderr, "GCM ", log.LstdFlags)

	encrypt    bool
	decrypt    bool
	keyString  string
	inputPath  string
	outputPath string
)

func main() {
	flag.BoolVar(&encrypt, "e", false, "Enrypt the given file")
	flag.BoolVar(&decrypt, "d", false, "Decrypt the given file")
	flag.StringVar(&keyString, "K", "", "The hex encoded key")
	flag.StringVar(&inputPath, "in", "", "The input file")
	flag.StringVar(&outputPath, "out", "", "The output file")
	flag.Parse()
	checkRequiredFlags()
	key, err := hex.DecodeString(keyString)
	if err != nil || len(key) != keySize {
		logger.Fatalln("Invalid key. Must be a valid %d byte hex encoded string\n", keySize)
	}
	if encrypt {
		err = encryptFile(inputPath, outputPath, key)
	} else if decrypt {
		err = decryptFile(inputPath, outputPath, key)
	}
	if err != nil {
		log.Fatalln(err.Error())
	}
}

func encryptFile(inFilePath, outFilePath string, key []byte) error {
	if _, err := os.Stat(inFilePath); os.IsNotExist(err) {
		return fmt.Errorf("A file does not exist at %s", inFilePath)
	}
	if _, err := os.Stat(outFilePath); err == nil {
		logger.Printf("Overwriting output file %s\n", outFilePath)
	}

	inFile, err := os.Open(inFilePath)
	defer inFile.Close()
	if err != nil {
		return err
	}

	outFile, err := os.OpenFile(outFilePath, os.O_CREATE|os.O_RDWR, 0600)
	defer outFile.Close()
	if err != nil {
		return err
	}

	aes, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return err
	}

	var counter uint64
	for {
		iv := counterToIV(counter, gcm.NonceSize())
		chunk := make([]byte, chunkSize)
		read, _ := inFile.Read(chunk)
		if read == 0 {
			break
		}
		encrChunk := gcm.Seal(nil, iv, chunk[:read], []byte("catalyzecatalyze"))
		outFile.Write(encrChunk)
		counter++
	}
	return nil
}

func decryptFile(inFilePath, outFilePath string, key []byte) error {
	if _, err := os.Stat(inFilePath); os.IsNotExist(err) {
		return fmt.Errorf("A file does not exist at %s", inFilePath)
	}
	if _, err := os.Stat(outFilePath); err == nil {
		logger.Printf("Overwriting output file %s\n", outFilePath)
	}

	inFile, err := os.Open(inFilePath)
	defer inFile.Close()
	if err != nil {
		return err
	}

	outFile, err := os.OpenFile(outFilePath, os.O_CREATE|os.O_RDWR, 0600)
	defer outFile.Close()
	if err != nil {
		return err
	}

	aes, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return err
	}

	var counter uint64
	for {
		iv := counterToIV(counter, gcm.NonceSize())
		chunk := make([]byte, chunkSize+gcm.Overhead())
		read, _ := inFile.Read(chunk)
		if read == 0 {
			break
		}
		decrChunk, err := gcm.Open(nil, iv, chunk[:read], []byte("catalyzecatalyze"))
		if err != nil {
			return err
		}
		outFile.Write(decrChunk)
		counter++
	}
	return nil
}

func counterToIV(counter uint64, size int) []byte {
	b := make([]byte, size)
	binary.LittleEndian.PutUint64(b, counter)
	return b
}

func checkRequiredFlags() {
	if (encrypt && decrypt) || (!encrypt && !decrypt) {
		logger.Fatalln("-e or -d must be specified, but not both")
	}
	if keyString == "" {
		logger.Fatalln("-K is required")
	}
	if inputPath == "" {
		logger.Fatalln("-in is required")
	}
	if outputPath == "" {
		logger.Fatalln("-out is required")
	}
}
