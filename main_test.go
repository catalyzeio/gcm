package main

import (
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

// http://www.mail-archive.com/stds-p1619@listserv.ieee.org/msg00548.html

type GCMInput struct {
	VEC string // Test vector number (in decimal)
	KEY string // 256-bit encryption key
	IV  string // Initialization vector
	HDR string // AAD (Additional Authentication Data)
	RPT int    // Repeat the previous HDR (AAD) a given number of times
	PTX string // Plaintext
	CTX string // Ciphertext
	TAG string // MAC (Message Authentication Code)
}

/*var testData = []GCMInput{
	{
		VEC: "0001",
		KEY: "0000000000000000000000000000000000000000000000000000000000000000",
		IV:  "000000000000000000000000",
		PTX: "00000000000000000000000000000000",
		CTX: "cea7403d4d606b6e074ec5d3baf39d18",
		TAG: "d0d1c8a799996bf0265b98b5d48ab919",
	},
	{
		VEC: "0002",
		KEY: "0000000000000000000000000000000000000000000000000000000000000000",
		IV:  "000000000000000000000000",
		HDR: "00000000000000000000000000000000",
		TAG: "2d45552d8575922b3ca3cc538442fa26",
	},
	{
		VEC: "0003",
		KEY: "0000000000000000000000000000000000000000000000000000000000000000",
		IV:  "000000000000000000000000",
		HDR: "00000000000000000000000000000000",
		PTX: "00000000000000000000000000000000",
		CTX: "cea7403d4d606b6e074ec5d3baf39d18",
		TAG: "ae9b1771dba9cf62b39be017940330b4",
	},
	{
		VEC: "0004",
		KEY: "fb7615b23d80891dd470980bc79584c8b2fb64ce60978f4d17fce45a49e830b7",
		IV:  "dbd1a3636024b7b402da7d6f",
		PTX: "a845348ec8c5b5f126f50e76fefd1b1e",
		CTX: "5df5d1fabcbbdd051538252444178704",
		TAG: "4c43cce5a574d8a88b43d4353bd60f9f",
	},
	{
		VEC: "0005",
		KEY: "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
		IV:  "101112131415161718191a1b",
		HDR: "000102030405060708090a0b0c0d0e0f10111213",
		PTX: "202122232425262728292a2b2c2d2e2f3031323334353637",
		CTX: "591b1ff272b43204868ffc7bc7d521993526b6fa32247c3c",
		TAG: "7de12a5670e570d8cae624a16df09c08",
	},
	{
		VEC: "0006",
		KEY: "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
		IV:  "101112131415161718191a1b",
		HDR: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
			"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
			"404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" +
			"606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" +
			"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" +
			"a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
			"c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
			"e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		RPT: 0256,
		PTX: "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
		CTX: "591b1ff272b43204868ffc7bc7d521993526b6fa32247c3c4057f3eae7548cef",
		TAG: "a1de5536e97edddccd26eeb1b5ff7b32",
	},
	{
		VEC: "0007",
		KEY: "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
		IV:  "101112131415161718191a1b",
		HDR: "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
		PTX: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
			"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
			"404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f" +
			"606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" +
			"808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f" +
			"a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
			"c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
			"e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		CTX: "793b3fd252941224a6afdc5be7f501b9150696da12045c1c6077d3cac774accf" +
			"c3d530d848d665d81a49cbb500b88bbb624ae61d1667229c302dc6ff0bb4d70b" +
			"dbbc8566d6f5b158da99a2ff2e01dda629b89c34ad1e5feba70e7aae4328289c" +
			"3629b0588350581ca8b97ccf1258fa3bbe2c5026047ba72648969cff8ba10ae3" +
			"0e05935df0c693741892b76faf67133abd2cf2031121bd8bb38127a4d2eedeea" +
			"13276494f402cd7c107fb3ec3b24784834338e55436287092ac4a26f5ea7ea4a" +
			"d68d73151639b05b24e68b9816d1398376d8e4138594758db9ad3b409259b26d" +
			"cfc06e722be987b3767f70a7b856b774b1ba2685b368091429fccb8dcdde09e4",
		TAG: "87ec837abf532855b2cea169d6943fcd",
	},
	{
		VEC: "0008",
		KEY: "fb7615b23d80891dd470980bc79584c8b2fb64ce6097878d17fce45a49e830b7",
		IV:  "dbd1a3636024b7b402da7d6f",
		HDR: "36",
		PTX: "a9",
		CTX: "0a",
		TAG: "be987d009a4b349aa80cb9c4ebc1e9f4",
	},
	{
		VEC: "0009",
		KEY: "f8d476cfd646ea6c2384cb1c27d6195dfef1a9f37b9c8d21a79c21f8cb90d289",
		IV:  "dbd1a3636024b7b402da7d6f",
		HDR: "7bd859a247961a21823b380e9fe8b65082ba61d3",
		PTX: "90ae61cf7baebd4cade494c54a29ae70269aec71",
		CTX: "ce2027b47a843252013465834d75fd0f0729752e",
		TAG: "acd8833837ab0ede84f4748da8899c15",
	},
	{
		VEC: "0010",
		KEY: "dbbc8566d6f5b158da99a2ff2e01dda629b89c34ad1e5feba70e7aae4328289c",
		IV:  "cfc06e722be987b3767f70a7b856b774",
		PTX: "ce2027b47a843252013465834d75fd0f",
		CTX: "0330ea65b1f48ad718c3f1f3dcefe420",
		TAG: "e9efa997d0ae824290bb5a6695ff2c7a",
	},
	{
		VEC: "0011",
		KEY: "0e05935df0c693741892b76faf67133abd2cf2031121bd8bb38127a4d2eedeea",
		IV:  "74b1ba2685b368091429fccb8dcdde09e4",
		HDR: "7bd859a247961a21823b380e9fe8b65082ba61d3",
		PTX: "90ae61cf7baebd4cade494c54a29ae70269aec71",
		CTX: "6be65e56066c4056738c03fe2320974ba3f65e09",
		TAG: "6108dc417bf32f7fb7554ae52f088f87",
	},
}*/

var testData = []GCMInput{
	{
		VEC: "0001",
		KEY: "00000000000000000000000000000000",
		IV:  "000000000000000000000000",
		HDR: "66e94bd4ef8a2c3b884cfa59ca342b2e",
		TAG: "58e2fccefa7e3061367f1d57a4e7455a",
	},
}

func TestGCM(t *testing.T) {
	for _, input := range testData {
		inputFileName := fmt.Sprintf("input%s.dat", input.VEC)
		outputFileName := fmt.Sprintf("output%s.dat", input.VEC)
		defer os.Remove(inputFileName)
		defer os.Remove(outputFileName)

		var key, iv, hdr, plainText, cipherText, tag []byte
		var err error

		if input.KEY != "" {
			key, err = hex.DecodeString(input.KEY)
			if err != nil {
				t.Errorf("VEC %s failed. Failed to decode KEY: %v", input.VEC, err.Error())
				continue
			}
		}

		if input.IV != "" {
			iv, err = hex.DecodeString(input.IV)
			if err != nil {
				t.Errorf("VEC %s failed. Failed to decode IV: %v", input.VEC, err.Error())
				continue
			}
		}

		if input.HDR != "" {
			hdr, err = hex.DecodeString(input.HDR)
			if err != nil {
				t.Errorf("VEC %s failed. Failed to decode HDR: %v", input.VEC, err.Error())
				continue
			}
		}

		aad := hdr
		for i := 1; i < input.RPT; i++ {
			aad = append(aad, hdr...)
		}

		if input.PTX != "" {
			plainText, err = hex.DecodeString(input.PTX)
			if err != nil {
				t.Errorf("VEC %s failed. Failed to decode PTX: %v", input.VEC, err.Error())
				continue
			}
		}

		err = ioutil.WriteFile(inputFileName, plainText, 0644)
		if err != nil {
			t.Errorf("VEC %s failed. Failed to write PTX to file: %v", input.VEC, err.Error())
			continue
		}

		err = encryptFile(inputFileName, outputFileName, key, iv, aad)
		if err != nil {
			t.Errorf("VEC %s failed: %v", input.VEC, err.Error())
			continue
		}

		output, err := ioutil.ReadFile(outputFileName)
		if err != nil {
			t.Errorf("VEC %s failed. Failed to read output file: %v", input.VEC, err.Error())
			continue
		}

		if input.CTX != "" {
			cipherText, err = hex.DecodeString(input.CTX)
			if err != nil {
				t.Errorf("VEC %s failed. Failed to decode CTX: %v", input.VEC, err.Error())
				continue
			}
		}

		if input.TAG != "" {
			tag, err = hex.DecodeString(input.TAG)
			if err != nil {
				t.Errorf("VEC %s failed. Failed to decode TAG: %v", input.VEC, err.Error())
				continue
			}
		}

		if len(output) >= 16 {
			if subtle.ConstantTimeCompare(output[:len(output)-16], cipherText) != 1 {
				t.Errorf("VEC %s failed. CTX differs: %x != %x", input.VEC, output[:len(output)-16], cipherText)
				continue
			}
			if subtle.ConstantTimeCompare(output[len(output)-16:], tag) != 1 {
				t.Errorf("VEC %s failed. TAG differs: %x != %x", input.VEC, output[len(output)-16:], tag)
				continue
			}
		} else {
			if subtle.ConstantTimeCompare([]byte{}, cipherText) != 1 {
				t.Errorf("VEC %s failed. CTX differs: %x != %x", input.VEC, []byte{}, cipherText)
				continue
			}
			if subtle.ConstantTimeCompare(output, tag) != 1 {
				t.Errorf("VEC %s failed. TAG differs: %x != %x", input.VEC, output, tag)
				continue
			}
		}
	}
}