package gcm

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"os"
	"sync"
)

const (
	chunkSize = 1024 * 1024 // 1 MB

	// AAD (Additional authenticated data) is to be used in the GCM algorithm
	AAD = "7f57c07ee9459ed704d5e403086f6503"
)

// EncryptFile encrypts the file at the specified path using GCM.
func EncryptFile(inFilePath, outFilePath string, key, givenIV, aad []byte) error {
	efr, err := NewEncryptFileReader(inFilePath, key, givenIV, aad)
	defer efr.Close()
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

// EncryptFileReader is an io.ReadCloser interface that encrypts a file
// into Read calls.
type EncryptFileReader struct {
	file        *os.File
	gcm         cipher.AEAD
	aad         []byte
	iv          []byte
	leftOver    []byte
	chunk       []byte
	doneReading bool
	written     bool
	readLock    *sync.Mutex
}

// Read is the encrypting stream method. It reads from its file
// at a particular chunk size, which may be bigger or smaller than
// the buffer passed to this Read method. It then decrypts this fixed-size
// chunk read into a member (leftOver) and copies as much of this saved buffer
// into the passed buffer-argument as it can. If it cannot copy the entire
// "leftOver" buffer it passes the remainder in the subsequent call(s). When
// "leftOver" buffer reaches 0 a chunk read happens again, unitl the file
// returns an io.EOF. This Read method will return its io.EOF when it has
// received an io.EOF from its file AND the "leftOver" buffer reaches 0.
func (efr *EncryptFileReader) Read(p []byte) (int, error) {
	efr.readLock.Lock()
	defer efr.readLock.Unlock()
	if !efr.doneReading && len(efr.leftOver) == 0 {
		read, err := efr.file.Read(efr.chunk)
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
	copied := copy(p, efr.leftOver)
	efr.leftOver = efr.leftOver[copied:]
	if efr.doneReading && len(efr.leftOver) == 0 {
		return copied, io.EOF
	}
	return copied, nil
}

// Close closes the file.
func (efr *EncryptFileReader) Close() error {
	efr.readLock.Lock()
	defer efr.readLock.Unlock()
	// Close can handle nil calls
	err := efr.file.Close()
	efr.file = nil
	return err
}

// NewEncryptFileReader creates an instance of EncryptFileReader, which implements io.ReaderCloser,
// which encrypts its given file in chunks as its Read method is called.
func NewEncryptFileReader(inFilePath string, key, givenIV, aad []byte) (*EncryptFileReader, error) {
	efr := new(EncryptFileReader)
	efr.chunk = make([]byte, chunkSize)
	efr.doneReading = false
	efr.written = false
	efr.readLock = &sync.Mutex{}
	var err error
	if _, err = os.Stat(inFilePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("A file does not exist at %s", inFilePath)
	}
	efr.file, err = os.Open(inFilePath)
	if err != nil {
		return nil, err
	}
	// make our own copy so that it won't get modified
	efr.aad = make([]byte, len(aad))
	copy(efr.aad, aad)
	// copy the IV since it will potentially be incremented
	efr.iv = make([]byte, len(givenIV))
	copy(efr.iv, givenIV)

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

// DecryptFile decrypts the file at the specified path using GCM.
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

// DecryptFileWriterAt is an io.WriterAt and io.Closer interfaces that decrypts
// WriterAt calls to a file.
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

// WriteAt is the decrypting stream method for DecryptFileWriterAt.
// It will always the bytes written as the length of the passed buffer. This is a lie.
// It works by saving byte chunks in a map of offsets as a moving buffer,
// keeping track of a partial view of the buffer.
// When it has a complete set of offsets that it can write, without gaps,
// it copies the offsets to a chunk buffer, a fixed size buffer, required
// for correct writes to the gcm.Open function. When this fixed size buffer
// is filled it is decrypted and the resulting decryption is written
// to the file. When the DecryptFileWriterAt Close function is called,
// any remaining buffer in the "chunk" buffer is decrypted and written
// to the file, which is then closed.
func (dfw *DecryptFileWriterAt) WriteAt(p []byte, off int64) (int, error) {
	lenP := len(p)
	dfw.writeLock.Lock()
	defer dfw.writeLock.Unlock()
	if off == dfw.nextOff {
		// This doesn't need to be copied, because we know it's about to get copied to
		// the chunk buffer.
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

// Close flushes any remaining buffer and closes the input file.
func (dfw *DecryptFileWriterAt) Close() error {
	dfw.writeLock.Lock()
	defer dfw.writeLock.Unlock()
	var err error
	var err2 error
	if dfw.chunkCopied > 0 || !dfw.written {
		err = dfw.flushChunk()
	}
	// Close can handle nil calls
	err2 = dfw.file.Close()
	dfw.file = nil
	if err2 != nil {
		if err == nil {
			return err2
		}
		return fmt.Errorf("%v\n%v", err, err2)
	}
	return err
}

func (dfw *DecryptFileWriterAt) copyToChunk(p []byte, lenP int) error {
	copied := copy(dfw.chunk[dfw.chunkCopied:], p)
	dfw.chunkCopied += copied
	if dfw.chunkCopied == dfw.chunkL {
		if err := dfw.flushChunk(); err != nil {
			return err
		}
	}
	lenP -= copied
	if lenP > 0 {
		return dfw.copyToChunk(p[copied:], lenP)
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

// NewDecryptFileWriterAt creates an instance of NewDecryptFileWriterAt, which decrypts
// WrittenAt chunks into the given file path.
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
