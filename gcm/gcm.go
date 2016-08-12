package gcm

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
)

const (
	chunkSize = 1024 * 1024 // 1 MB

	// AAD (Additional authenticated data) is to be used in the GCM algorithm
	AAD = "7f57c07ee9459ed704d5e403086f6503"
)

// EncryptFile encrypts the file at the specified path using GCM
func EncryptFile(inFilePath, outFilePath string, key, givenIV, aad []byte) error {
	efr, err := NewEncryptFileReader(inFilePath, key, givenIV, aad)
	if err != nil {
		return err
	}
	outFile, err := os.OpenFile(outFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer outFile.Close()
	chunk := make([]byte, chunkSize)
	written := false
	for {
		read, err := efr.Read(chunk)
		if err != nil && err != io.EOF {
			return err
		}
		if read > 0 || !written {
			if _, err := outFile.Write(chunk[:read]); err != nil {
				return err
			}
			written = true
		}
		if err == io.EOF {
			break
		}
	}
	return nil
}

/*func EncryptFile(inFilePath, outFilePath string, key, givenIV, aad []byte) error {
	if _, err := os.Stat(inFilePath); os.IsNotExist(err) {
		return fmt.Errorf("A file does not exist at %s", inFilePath)
	}
	// copy the IV since it will potentially be incremented
	iv := make([]byte, len(givenIV))
	copy(iv, givenIV)

	inFile, err := os.Open(inFilePath)
	if err != nil {
		return err
	}
	defer inFile.Close()
	outFile, err := os.OpenFile(outFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
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
	written := false
	for {
		read, err := inFile.Read(chunk)
		// ensure we have written at least one chunk before breaking
		if read > 0 || !written {
			encrChunk := gcm.Seal(nil, iv, chunk[:read], aad)
			if _, err := outFile.Write(encrChunk); err != nil {
				return err
			}
			written = true
		}
		if err == io.EOF {
			break
		}
		incrementIV(iv)
	}
	return nil
}*/

// EncryptFileReader is an io.Reader interface that encrypts a file
type EncryptFileReader struct {
	file        *os.File
	gcm         cipher.AEAD
	aad         []byte
	iv          []byte
	leftOver    []byte
	chunk       []byte
	doneReading bool
	written     bool
}

// Read is the encrypting stream method
func (efr *EncryptFileReader) Read(p []byte) (int, error) {
	lenP := len(p)
	if lenP == 0 {
		return 0, nil
	}
	var read int
	var err error
	if efr.leftOver == nil && !efr.doneReading {
		read, err = efr.file.Read(efr.chunk)
		if err != nil && err != io.EOF {
			return 0, err
		}
		if read > 0 || !efr.written {
			efr.leftOver = efr.gcm.Seal(nil, efr.iv, efr.chunk[:read], efr.aad)
			incrementIV(efr.iv)
			efr.written = true
		}
		if err == io.EOF {
			efr.doneReading = true
		}
	}
	lenLO := len(efr.leftOver)
	err = nil
	if lenLO <= lenP {
		if efr.doneReading {
			err = io.EOF
		}
		copy(p, efr.leftOver)
		efr.leftOver = nil
		return lenLO, err
	}
	copy(p, efr.leftOver[:lenP])
	efr.leftOver = efr.leftOver[lenP:]
	return lenP, nil
}

func encryptFileReaderFinalizer(efr *EncryptFileReader) {
	if efr.file != nil {
		efr.file.Close()
		efr.file = nil
	}
}

// NewEncryptFileReader creates an instance of EncryptFileReader
func NewEncryptFileReader(inFilePath string, key, givenIV, aad []byte) (*EncryptFileReader, error) {
	efr := new(EncryptFileReader)
	efr.chunk = make([]byte, chunkSize)
	efr.doneReading = false
	efr.written = false
	var err error
	if _, err = os.Stat(inFilePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("A file does not exist at %s", inFilePath)
	}
	// make our own copy so that it won't get modified
	efr.aad = make([]byte, len(aad))
	copy(efr.aad, aad)
	// copy the IV since it will potentially be incremented
	efr.iv = make([]byte, len(givenIV))
	copy(efr.iv, givenIV)

	efr.file, err = os.Open(inFilePath)
	if err != nil {
		return nil, err
	}
	runtime.SetFinalizer(efr, encryptFileReaderFinalizer)

	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	efr.gcm, err = cipher.NewGCMWithNonceSize(aes, len(efr.iv))
	if err != nil {
		return nil, err
	}
	return efr, nil
}

// DecryptFile decrypts the file at the specified path using GCM
func DecryptFile(inFilePath, outFilePath string, key, givenIV, aad []byte) error {
	dfw, err := NewDecryptFileWriterAt(outFilePath, key, givenIV, aad)
	defer dfw.Close()
	if err != nil {
		return err
	}
	inFile, err := os.Open(inFilePath)
	if err != nil {
		return err
	}
	defer inFile.Close()
	written := false
	chunk := make([]byte, chunkSize)
	var off int64
	for {
		read, err := inFile.Read(chunk)
		if err != nil && err != io.EOF {
			return err
		}
		// ensure we have written at least one chunk before breaking
		if read > 0 || !written {
			_, err := dfw.WriteAt(chunk[:read], off)
			if err != nil {
				return err
			}
			off += int64(read)
			written = true
		}
		if err == io.EOF {
			break
		}
	}
	return nil
}

/*func DecryptFile(inFilePath, outFilePath string, key, givenIV, aad []byte) error {
	if _, err := os.Stat(inFilePath); os.IsNotExist(err) {
		return fmt.Errorf("A file does not exist at %s", inFilePath)
	}
	// copy the IV since it will potentially be incremented
	iv := make([]byte, len(givenIV))
	copy(iv, givenIV)

	inFile, err := os.Open(inFilePath)
	if err != nil {
		return err
	}
	defer inFile.Close()

	outFile, err := os.OpenFile(outFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
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

	written := false
	chunk := make([]byte, chunkSize+gcm.Overhead())
	for {
		read, err := inFile.Read(chunk)
		// ensure we have written at least one chunk before breaking
		if read > 0 || !written {
			decrChunk, err := gcm.Open(nil, iv, chunk[:read], aad)
			if err != nil {
				return err
			}
			if _, err := outFile.Write(decrChunk); err != nil {
				return err
			}
			written = true
		}
		if err == io.EOF {
			break
		}
		incrementIV(iv)
	}
	return nil
}*/

// DecryptFileWriterAt is an io.WriterAt interface that decrypts a file
type DecryptFileWriterAt struct {
	file        *os.File
	gcm         cipher.AEAD
	aad         []byte
	iv          []byte
	chunk       []byte
	chunkL      int
	chunkCopied int
	nextOff     int64
	bufferMap   map[int64][]byte
	writeLock   *sync.Mutex
	written     bool
}

// WriteAt is the decrypting stream method
func (dfw *DecryptFileWriterAt) WriteAt(p []byte, off int64) (int, error) {
	lenP := len(p)
	if lenP == 0 {
		return 0, nil
	}
	dfw.writeLock.Lock()
	defer dfw.writeLock.Unlock()
	if off == dfw.nextOff {
		dfw.bufferMap[off] = p
		for buf, ok := dfw.bufferMap[dfw.nextOff]; ok; buf, ok = dfw.bufferMap[dfw.nextOff] {
			lenB := len(buf)
			err := dfw.copyToChunk(buf, lenB)
			if err != nil {
				return 0, err
			}
			delete(dfw.bufferMap, dfw.nextOff)
			dfw.nextOff += int64(lenB)
		}
	} else {
		dfw.bufferMap[off] = make([]byte, lenP)
		copy(dfw.bufferMap[off], p)
	}
	return lenP, nil
}

// Close flushes any remaining buffer and closes the input file
func (dfw *DecryptFileWriterAt) Close() error {
	dfw.writeLock.Lock()
	defer dfw.writeLock.Unlock()
	var err error
	if dfw.chunkCopied > 0 || !dfw.written {
		err = dfw.flushChunk()
	}
	if dfw.file != nil {
		err2 := dfw.file.Close()
		dfw.file = nil
		if err2 != nil {
			if err == nil {
				return err2
			}
			return fmt.Errorf("%s\n%s", err, err2)
		}
	}
	return err
}

func (dfw *DecryptFileWriterAt) copyToChunk(p []byte, pLen int) error {
	copied := copy(dfw.chunk[dfw.chunkCopied:], p)
	dfw.chunkCopied += copied
	if dfw.chunkCopied == dfw.chunkL {
		dfw.flushChunk()
	}
	pLen -= copied
	if pLen > 0 {
		return dfw.copyToChunk(p[:copied], pLen)
	}
	return nil
}

func (dfw *DecryptFileWriterAt) flushChunk() error {
	decrChunk, err := dfw.gcm.Open(nil, dfw.iv, dfw.chunk[:dfw.chunkCopied], dfw.aad)
	if err != nil {
		return err
	}
	if _, err := dfw.file.Write(decrChunk); err != nil {
		return err
	}
	dfw.written = true
	dfw.chunkCopied = 0
	incrementIV(dfw.iv)
	return nil
}

func decryptFileWriterAtFinalizer(dfw *DecryptFileWriterAt) {
	dfw.Close()
}

// NewDecryptFileWriterAt creates an instance of NewDecryptFileWriterAt
func NewDecryptFileWriterAt(outFilePath string, key, givenIV, aad []byte) (*DecryptFileWriterAt, error) {
	dfw := new(DecryptFileWriterAt)
	dfw.nextOff = 0
	dfw.writeLock = &sync.Mutex{}
	dfw.bufferMap = make(map[int64][]byte)
	dfw.written = false
	var err error
	dfw.file, err = os.OpenFile(outFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return nil, err
	}
	runtime.SetFinalizer(dfw, decryptFileWriterAtFinalizer)
	// make our own copy so that it won't get modified
	dfw.aad = make([]byte, len(aad))
	copy(dfw.aad, aad)
	// copy the IV since it will potentially be incremented
	dfw.iv = make([]byte, len(givenIV))
	copy(dfw.iv, givenIV)

	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	dfw.gcm, err = cipher.NewGCMWithNonceSize(aes, len(dfw.iv))
	if err != nil {
		return nil, err
	}
	dfw.chunkL = chunkSize + dfw.gcm.Overhead()
	dfw.chunk = make([]byte, dfw.chunkL)
	return dfw, nil
}

func incrementIV(iv []byte) {
	for i := len(iv) - 1; i >= 0; i-- {
		iv[i]++
		if iv[i] != 0 {
			return
		}
	}
}
