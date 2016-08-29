package gcm

import (
	"crypto/aes"
	"crypto/cipher"
	"io"
	"os"
)

const (
	chunkSize = 1024 * 1024 // 1 MB

	// AAD (Additional authenticated data) is to be used in the GCM algorithm
	AAD = "7f57c07ee9459ed704d5e403086f6503"
)

// EncryptFile encrypts the file at the specified path using GCM.
func EncryptFile(inFilePath, outFilePath string, key, givenIV, aad []byte) error {
	if _, err := os.Stat(inFilePath); os.IsNotExist(err) {
		return err
	}
	file, err := os.Open(inFilePath)
	if err != nil {
		return err
	}
	defer file.Close()
	efr, err := NewEncryptFileReader(file, key, givenIV, aad)
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

// EncryptFileReader is an io.Reader interface that encrypts its
// read calls into another io.Reader interface
type EncryptFileReader struct {
	reader      io.Reader
	gcm         cipher.AEAD
	aad         []byte
	iv          []byte
	leftOver    []byte
	chunk       []byte
	doneReading bool
	written     bool
}

// Read is the encrypting stream method. It reads from its io.Reader
// at a particular chunk size, which may be bigger or smaller than
// the buffer passed to this Read method. It then decrypts this fixed-size
// chunk read into a member (leftOver) and copies as much of this saved buffer
// into the passed buffer-argument as it can. If it cannot copy the entire
// "leftOver" buffer it passes the remainder in the subsequent call(s). When
// "leftOver" buffer reaches 0 a chunk read happens again, unitl the reader
// returns an io.EOF. This Read method will return its io.EOF when it has
// received an io.EOF from its file AND the "leftOver" buffer reaches 0.
func (efr *EncryptFileReader) Read(p []byte) (int, error) {
	if !efr.doneReading && len(efr.leftOver) == 0 {
		read, err := efr.reader.Read(efr.chunk)
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

// NewEncryptFileReader creates an instance of EncryptFileReader, which implements io.ReaderCloser,
// which encrypts its given io.Reader in chunks as its Read method is called.
func NewEncryptFileReader(reader io.Reader, key, givenIV, aad []byte) (*EncryptFileReader, error) {
	efr := new(EncryptFileReader)
	efr.reader = reader
	efr.chunk = make([]byte, chunkSize)
	efr.doneReading = false
	efr.written = false
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
	outFile, err := os.OpenFile(outFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	dfw, err := NewDecryptFileWriteCloser(outFile, key, givenIV, aad)
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
	for {
		read, err := inFile.Read(chunk)
		if err != nil && err != io.EOF {
			return err
		}
		// ensure we have written at least one chunk before breaking
		if read > 0 || !written {
			_, err := dfw.Write(chunk[:read])
			if err != nil {
				return err
			}
			written = true
		}
		if err == io.EOF {
			break
		}
	}
	return dfw.Close()
}

// DecryptFileWriteCloser is an io.WriteCloser interface that decrypts
// it Write calls into another io.WriteCloser interface
type DecryptFileWriteCloser struct {
	writeCloser io.WriteCloser
	written     bool
	gcm         cipher.AEAD
	aad         []byte
	iv          []byte
	chunk       []byte
	chunkL      int
	chunkCopied int
}

// Write copies the passed write buffer into a fixed chunk size
// that GCM accepts. The bytes are only flushed to the underlying
// io.WriteCloser when the chunk buffer reaches this size OR on
// the last Write call (i.e. the remaining, last bytes).
func (dfw *DecryptFileWriteCloser) Write(p []byte) (int, error) {
	copied := copy(dfw.chunk[dfw.chunkCopied:], p)
	dfw.chunkCopied += copied
	if dfw.chunkCopied == dfw.chunkL {
		if err := dfw.flushChunk(); err != nil {
			return copied, err
		}
	}
	pRemainder := p[copied:]
	if len(pRemainder) > 0 {
		tmp, err := dfw.Write(pRemainder)
		return tmp + copied, err
	}
	return copied, nil
}

// Close flushes any remaining bytes that have not been written to
// the underlying io.WriteCloser, and closes the underlying io.WriteCloser
func (dfw *DecryptFileWriteCloser) Close() error {
	if err := dfw.flushChunk(); err != nil {
		return err
	}
	return dfw.writeCloser.Close()
}

func (dfw *DecryptFileWriteCloser) flushChunk() error {
	if dfw.chunkCopied > 0 || !dfw.written {
		decrChunk, err := dfw.gcm.Open(nil, dfw.iv, dfw.chunk[:dfw.chunkCopied], dfw.aad)
		if err != nil {
			return err
		}
		if _, err := dfw.writeCloser.Write(decrChunk); err != nil {
			return err
		}
		incrementIV(dfw.iv)
		dfw.chunkCopied = 0
		dfw.written = true
	}
	return nil
}

// NewDecryptFileWriteCloser creates an instance of DecryptFileWriteCloser, which decrypts
// io.Writer chunks into the given io.Writer. The type is a Closer, because it must be closed to
// Write all data its been given (i.e. told when the "last" write is happening).
func NewDecryptFileWriteCloser(writeCloser io.WriteCloser, key, givenIV, aad []byte) (*DecryptFileWriteCloser, error) {
	dfw := new(DecryptFileWriteCloser)
	dfw.writeCloser = writeCloser
	dfw.written = false
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
