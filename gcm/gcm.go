package gcm

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"os"
)

const (
	chunkSize = 1024 * 1024 // 1 MB

	// AAD (Additional authenticated data) is to be used in the GCM algorithm
	AAD = "7f57c07ee9459ed704d5e403086f6503"
)

// EncryptFile encrypts the file at the specified path using GCM
func EncryptFile(inFilePath, outFilePath string, key, iv, aad []byte) error {
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

// DecryptFile decrypts the file at the specified path using GCM
func DecryptFile(inFilePath, outFilePath string, key, iv, aad []byte) error {
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
