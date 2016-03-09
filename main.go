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
		err = encryptFile(inputPath, outputPath, key, make([]byte, 12), []byte("catalyze"))
	} else if decrypt {
		err = decryptFile(inputPath, outputPath, key, make([]byte, 12), []byte("catalyze"))
	}
	if err != nil {
		log.Fatalln(err.Error())
	}
}

func encryptFile(inFilePath, outFilePath string, key, iv, aad []byte) error {
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
	//gcm, err := cipher.NewGCMWithNonceSize(aes, len(iv))
	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return err
	}

	for {
		chunk := make([]byte, chunkSize)
		read, _ := inFile.Read(chunk)
		encrChunk := gcm.Seal(nil, iv, chunk[:read], aad)
		outFile.Write(encrChunk)
		if read == 0 {
			break
		}
		iv = incrementIV(iv)
	}
	return nil
}

func decryptFile(inFilePath, outFilePath string, key, iv, aad []byte) error {
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
	//gcm, err := cipher.NewGCMWithNonceSize(aes, len(iv))
	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return err
	}

	for {
		chunk := make([]byte, chunkSize+gcm.Overhead())
		read, _ := inFile.Read(chunk)
		decrChunk, err := gcm.Open(nil, iv, chunk[:read], aad)
		if err != nil {
			return err
		}
		outFile.Write(decrChunk)
		if read == 0 {
			break
		}
		iv = incrementIV(iv)
	}
	return nil
}

func incrementIV(iv []byte) []byte {
	i := binary.LittleEndian.Uint64(iv)
	i++
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, i)
	b = append(b, iv[8:]...)
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
