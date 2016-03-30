# GCM

A simple command line utility for encrypting and decrypting files of any size using Galois/Counter Mode (GCM). This is a wrapper around the Golang implementation of GCM.

## Usage

The following flags are required for both encryption and decryption

| Flag | Description |
|------|-------------|
| -K | The hex encoded key |
| -iv | The hex encoded IV |
| -in | The input file |
| -out | The output file |

Further, you must specify one of `-e` for encryption or `-d` for decryption.

To encrypt a file, run

```
gcm -e -K fb7615b23d80891dd470980bc79584c8b2fb64ce60978f4d17fce45a49e830b7 -iv dbd1a3636024b7b402da7d6f -in data.txt -out data.txt.enc
```

Then to decrypt the file, run

```
gcm -d -K fb7615b23d80891dd470980bc79584c8b2fb64ce60978f4d17fce45a49e830b7 -iv dbd1a3636024b7b402da7d6f -in data.txt.enc -out data.txt
```

## Recommended Values

It is strongly recommended that the given key and IV follow these rules

* keys must be 32 bytes in length
* IVs should be 12 bytes in length
* keys and IVs never be reused in combination

## How it works

File encryption is achieved by splitting files into chunks of a predefined size (1 MB at this time) and performing GCM encryption on each chunk. The output of each operation is appended to a file. This entire output file is the final result of this GCM file encryption utility.

## Overhead

Because of the nature of all Authenticated Encryption with Associated Data (AEAD) algorithms, such as GCM, there is a small amount of overhead added to each piece of encrypted data. This additional piece of data, called the `TAG`, is a fixed size of 16 bytes. In this implementation, the TAG is appended to each encrypted chunk in the output file.

In total, this algorithm produces `16 bytes * ceil(plainTextFileSize bytes / 1048576 bytes)` of overhead (1048576 bytes is 1 MB). For a 1 MB file, the total encrypted file size will be `1048576 bytes + 16 bytes = 1048592 bytes`.

## Tests

This implementation passes all test samples from [IEEE](http://www.mail-archive.com/stds-p1619@listserv.ieee.org/msg00548.html) and [NIST](http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf). However, it should be noted that those test samples are designed for small inputs and not for large file encryption.
