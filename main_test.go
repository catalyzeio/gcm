package main

import (
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

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

var testData = []GCMInput{
	// begin IEEE samples
	// http://www.mail-archive.com/stds-p1619@listserv.ieee.org/msg00548.html
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
		RPT: 256,
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
	/*{
		VEC: "0010",
		KEY: "dbbc8566d6f5b158da99a2ff2e01dda629b89c34ad1e5feba70e7aae4328289c",
		IV:  "cfc06e722be987b3767f70a7b856b774",
		PTX: "ce2027b47a843252013465834d75fd0f",
		CTX: "0330ea65b1f48ad718c3f1f3dcefe420",
		TAG: "e9efa997d0ae824290bb5a6695ff2c7a",
	},*/
	{
		VEC: "0011",
		KEY: "0e05935df0c693741892b76faf67133abd2cf2031121bd8bb38127a4d2eedeea",
		IV:  "74b1ba2685b368091429fccb8dcdde09e4",
		HDR: "7bd859a247961a21823b380e9fe8b65082ba61d3",
		PTX: "90ae61cf7baebd4cade494c54a29ae70269aec71",
		CTX: "6be65e56066c4056738c03fe2320974ba3f65e09",
		TAG: "6108dc417bf32f7fb7554ae52f088f87",
	},

	// begin NIST samples
	// http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf
	{
		VEC: "1001",
		KEY: "00000000000000000000000000000000",
		IV:  "000000000000000000000000",
		TAG: "58e2fccefa7e3061367f1d57a4e7455a",
	},
	{
		VEC: "1002",
		KEY: "00000000000000000000000000000000",
		IV:  "000000000000000000000000",
		PTX: "00000000000000000000000000000000",
		CTX: "0388dace60b6a392f328c2b971b2fe78",
		TAG: "ab6e47d42cec13bdf53a67b21257bddf",
	},
	{
		VEC: "1003",
		KEY: "feffe9928665731c6d6a8f9467308308",
		IV:  "cafebabefacedbaddecaf888",
		PTX: "d9313225f88406e5a55909c5aff5269a" +
			"86a7a9531534f7da2e4c303d8a318a72" +
			"1c3c0c95956809532fcf0e2449a6b525" +
			"b16aedf5aa0de657ba637b391aafd255",
		CTX: "42831ec2217774244b7221b784d0d49c" +
			"e3aa212f2c02a4e035c17e2329aca12e" +
			"21d514b25466931c7d8f6a5aac84aa05" +
			"1ba30b396a0aac973d58e091473f5985",
		TAG: "4d5c2af327cd64a62cf35abd2ba6fab4",
	},
	{
		VEC: "1004",
		KEY: "feffe9928665731c6d6a8f9467308308",
		IV:  "cafebabefacedbaddecaf888",
		HDR: "feedfacedeadbeeffeedfacedeadbeef" +
			"abaddad2",
		PTX: "d9313225f88406e5a55909c5aff5269a" +
			"86a7a9531534f7da2e4c303d8a318a72" +
			"1c3c0c95956809532fcf0e2449a6b525" +
			"b16aedf5aa0de657ba637b39",
		CTX: "42831ec2217774244b7221b784d0d49c" +
			"e3aa212f2c02a4e035c17e2329aca12e" +
			"21d514b25466931c7d8f6a5aac84aa05" +
			"1ba30b396a0aac973d58e091",
		TAG: "5bc94fbc3221a5db94fae95ae7121a47",
	},
	{
		VEC: "1005",
		KEY: "feffe9928665731c6d6a8f9467308308",
		IV:  "cafebabefacedbad",
		HDR: "feedfacedeadbeeffeedfacedeadbeef" +
			"abaddad2",
		PTX: "d9313225f88406e5a55909c5aff5269a" +
			"86a7a9531534f7da2e4c303d8a318a72" +
			"1c3c0c95956809532fcf0e2449a6b525" +
			"b16aedf5aa0de657ba637b39",
		CTX: "61353b4c2806934a777ff51fa22a4755" +
			"699b2a714fcdc6f83766e5f97b6c7423" +
			"73806900e49f24b22b097544d4896b42" +
			"4989b5e1ebac0f07c23f4598",
		TAG: "3612d2e79e3b0785561be14aaca2fccb",
	},
	{
		VEC: "1006",
		KEY: "feffe9928665731c6d6a8f9467308308",
		IV: "9313225df88406e555909c5aff5269aa" +
			"6a7a9538534f7da1e4c303d2a318a728" +
			"c3c0c95156809539fcf0e2429a6b5254" +
			"16aedbf5a0de6a57a637b39b",
		HDR: "feedfacedeadbeeffeedfacedeadbeef" +
			"abaddad2",
		PTX: "d9313225f88406e5a55909c5aff5269a" +
			"86a7a9531534f7da2e4c303d8a318a72" +
			"1c3c0c95956809532fcf0e2449a6b525" +
			"b16aedf5aa0de657ba637b39",
		CTX: "8ce24998625615b603a033aca13fb894" +
			"be9112a5c3a211a8ba262a3cca7e2ca7" +
			"01e4a9a4fba43c90ccdcb281d48c7c6f" +
			"d62875d2aca417034c34aee5",
		TAG: "619cc5aefffe0bfa462af43c1699d050",
	},
	{
		VEC: "1007",
		KEY: "00000000000000000000000000000000" +
			"0000000000000000",
		IV:  "000000000000000000000000",
		TAG: "cd33b28ac773f74ba00ed1f312572435",
	},
	{
		VEC: "1008",
		KEY: "00000000000000000000000000000000" +
			"0000000000000000",
		IV:  "000000000000000000000000",
		PTX: "00000000000000000000000000000000",
		CTX: "98e7247c07f0fe411c267e4384b0f600",
		TAG: "2ff58d80033927ab8ef4d4587514f0fb",
	},
	{
		VEC: "1009",
		KEY: "feffe9928665731c6d6a8f9467308308" +
			"feffe9928665731c",
		IV: "cafebabefacedbaddecaf888",
		PTX: "d9313225f88406e5a55909c5aff5269a" +
			"86a7a9531534f7da2e4c303d8a318a72" +
			"1c3c0c95956809532fcf0e2449a6b525" +
			"b16aedf5aa0de657ba637b391aafd255",
		CTX: "3980ca0b3c00e841eb06fac4872a2757" +
			"859e1ceaa6efd984628593b40ca1e19c" +
			"7d773d00c144c525ac619d18c84a3f47" +
			"18e2448b2fe324d9ccda2710acade256",
		TAG: "9924a7c8587336bfb118024db8674a14",
	},
	{
		VEC: "1010",
		KEY: "feffe9928665731c6d6a8f9467308308" +
			"feffe9928665731c",
		IV: "cafebabefacedbaddecaf888",
		HDR: "feedfacedeadbeeffeedfacedeadbeef" +
			"abaddad2",
		PTX: "d9313225f88406e5a55909c5aff5269a" +
			"86a7a9531534f7da2e4c303d8a318a72" +
			"1c3c0c95956809532fcf0e2449a6b525" +
			"b16aedf5aa0de657ba637b39",
		CTX: "3980ca0b3c00e841eb06fac4872a2757" +
			"859e1ceaa6efd984628593b40ca1e19c" +
			"7d773d00c144c525ac619d18c84a3f47" +
			"18e2448b2fe324d9ccda2710",
		TAG: "2519498e80f1478f37ba55bd6d27618c",
	},
	{
		VEC: "1011",
		KEY: "feffe9928665731c6d6a8f9467308308" +
			"feffe9928665731c",
		IV: "cafebabefacedbad",
		HDR: "feedfacedeadbeeffeedfacedeadbeef" +
			"abaddad2",
		PTX: "d9313225f88406e5a55909c5aff5269a" +
			"86a7a9531534f7da2e4c303d8a318a72" +
			"1c3c0c95956809532fcf0e2449a6b525" +
			"b16aedf5aa0de657ba637b39",
		CTX: "0f10f599ae14a154ed24b36e25324db8" +
			"c566632ef2bbb34f8347280fc4507057" +
			"fddc29df9a471f75c66541d4d4dad1c9" +
			"e93a19a58e8b473fa0f062f7",
		TAG: "65dcc57fcf623a24094fcca40d3533f8",
	},
	{
		VEC: "1012",
		KEY: "feffe9928665731c6d6a8f9467308308" +
			"feffe9928665731c",
		IV: "9313225df88406e555909c5aff5269aa" +
			"6a7a9538534f7da1e4c303d2a318a728" +
			"c3c0c95156809539fcf0e2429a6b5254" +
			"16aedbf5a0de6a57a637b39b",
		HDR: "feedfacedeadbeeffeedfacedeadbeef" +
			"abaddad2",
		PTX: "d9313225f88406e5a55909c5aff5269a" +
			"86a7a9531534f7da2e4c303d8a318a72" +
			"1c3c0c95956809532fcf0e2449a6b525" +
			"b16aedf5aa0de657ba637b39",
		CTX: "d27e88681ce3243c4830165a8fdcf9ff" +
			"1de9a1d8e6b447ef6ef7b79828666e45" +
			"81e79012af34ddd9e2f037589b292db3" +
			"e67c036745fa22e7e9b7373b",
		TAG: "dcf566ff291c25bbb8568fc3d376a6d9",
	},
	{
		VEC: "1013",
		KEY: "00000000000000000000000000000000" +
			"00000000000000000000000000000000",
		IV:  "000000000000000000000000",
		TAG: "530f8afbc74536b9a963b4f1c4cb738b",
	},
	{
		VEC: "1014",
		KEY: "00000000000000000000000000000000" +
			"00000000000000000000000000000000",
		IV:  "000000000000000000000000",
		PTX: "00000000000000000000000000000000",
		CTX: "cea7403d4d606b6e074ec5d3baf39d18",
		TAG: "d0d1c8a799996bf0265b98b5d48ab919",
	},
	{
		VEC: "1015",
		KEY: "feffe9928665731c6d6a8f9467308308" +
			"feffe9928665731c6d6a8f9467308308",
		IV: "cafebabefacedbaddecaf888",
		PTX: "d9313225f88406e5a55909c5aff5269a" +
			"86a7a9531534f7da2e4c303d8a318a72" +
			"1c3c0c95956809532fcf0e2449a6b525" +
			"b16aedf5aa0de657ba637b391aafd255",
		CTX: "522dc1f099567d07f47f37a32a84427d" +
			"643a8cdcbfe5c0c97598a2bd2555d1aa" +
			"8cb08e48590dbb3da7b08b1056828838" +
			"c5f61e6393ba7a0abcc9f662898015ad",
		TAG: "b094dac5d93471bdec1a502270e3cc6c",
	},
	{
		VEC: "1016",
		KEY: "feffe9928665731c6d6a8f9467308308" +
			"feffe9928665731c6d6a8f9467308308",
		IV: "cafebabefacedbaddecaf888",
		HDR: "feedfacedeadbeeffeedfacedeadbeef" +
			"abaddad2",
		PTX: "d9313225f88406e5a55909c5aff5269a" +
			"86a7a9531534f7da2e4c303d8a318a72" +
			"1c3c0c95956809532fcf0e2449a6b525" +
			"b16aedf5aa0de657ba637b39",
		CTX: "522dc1f099567d07f47f37a32a84427d" +
			"643a8cdcbfe5c0c97598a2bd2555d1aa" +
			"8cb08e48590dbb3da7b08b1056828838" +
			"c5f61e6393ba7a0abcc9f662",
		TAG: "76fc6ece0f4e1768cddf8853bb2d551b",
	},
	{
		VEC: "1017",
		KEY: "feffe9928665731c6d6a8f9467308308" +
			"feffe9928665731c6d6a8f9467308308",
		IV: "cafebabefacedbad",
		HDR: "feedfacedeadbeeffeedfacedeadbeef" +
			"abaddad2",
		PTX: "d9313225f88406e5a55909c5aff5269a" +
			"86a7a9531534f7da2e4c303d8a318a72" +
			"1c3c0c95956809532fcf0e2449a6b525" +
			"b16aedf5aa0de657ba637b39",
		CTX: "c3762df1ca787d32ae47c13bf19844cb" +
			"af1ae14d0b976afac52ff7d79bba9de0" +
			"feb582d33934a4f0954cc2363bc73f78" +
			"62ac430e64abe499f47c9b1f",
		TAG: "3a337dbf46a792c45e454913fe2ea8f2",
	},
	{
		VEC: "1018",
		KEY: "feffe9928665731c6d6a8f9467308308" +
			"feffe9928665731c6d6a8f9467308308",
		IV: "9313225df88406e555909c5aff5269aa" +
			"6a7a9538534f7da1e4c303d2a318a728" +
			"c3c0c95156809539fcf0e2429a6b5254" +
			"16aedbf5a0de6a57a637b39b",
		HDR: "feedfacedeadbeeffeedfacedeadbeef" +
			"abaddad2",
		PTX: "d9313225f88406e5a55909c5aff5269a" +
			"86a7a9531534f7da2e4c303d8a318a72" +
			"1c3c0c95956809532fcf0e2449a6b525" +
			"b16aedf5aa0de657ba637b39",
		CTX: "5a8def2f0c9e53f1f75d7853659e2a20" +
			"eeb2b22aafde6419a058ab4f6f746bf4" +
			"0fc0c3b780f244452da3ebf1c5d82cde" +
			"a2418997200ef82e44ae7e3f",
		TAG: "a44a8266ee1c8eb0c8b5d4cf5ae9f19a",
	},
}

func TestGCM(t *testing.T) {
	for _, input := range testData {
		inputFileName := fmt.Sprintf("input%s.dat", input.VEC)
		outputFileName := fmt.Sprintf("output%s.dat", input.VEC)
		defer os.Remove(inputFileName)
		defer os.Remove(outputFileName)

		key, err := hex.DecodeString(input.KEY)
		if err != nil {
			t.Errorf("VEC %s failed. Failed to decode KEY: %v", input.VEC, err.Error())
			continue
		}

		iv, err := hex.DecodeString(input.IV)
		if err != nil {
			t.Errorf("VEC %s failed. Failed to decode IV: %v", input.VEC, err.Error())
			continue
		}

		hdr, err := hex.DecodeString(input.HDR)
		if err != nil {
			t.Errorf("VEC %s failed. Failed to decode HDR: %v", input.VEC, err.Error())
			continue
		}

		aad := hdr
		for i := 1; i < input.RPT; i++ {
			aad = append(aad, hdr...)
		}

		plainText, err := hex.DecodeString(input.PTX)
		if err != nil {
			t.Errorf("VEC %s failed. Failed to decode PTX: %v", input.VEC, err.Error())
			continue
		}

		err = ioutil.WriteFile(inputFileName, plainText, 0644)
		if err != nil {
			t.Errorf("VEC %s failed. Failed to write PTX to file: %v", input.VEC, err.Error())
			continue
		}

		err = encryptFile(inputFileName, outputFileName, key, iv, aad)
		if err != nil {
			t.Errorf("VEC %s encryption failed: %v", input.VEC, err.Error())
			continue
		}

		output, err := ioutil.ReadFile(outputFileName)
		if err != nil {
			t.Errorf("VEC %s failed. Failed to read output file: %v", input.VEC, err.Error())
			continue
		}

		cipherText, err := hex.DecodeString(input.CTX)
		if err != nil {
			t.Errorf("VEC %s failed. Failed to decode CTX: %v", input.VEC, err.Error())
			continue
		}

		tag, err := hex.DecodeString(input.TAG)
		if err != nil {
			t.Errorf("VEC %s failed. Failed to decode TAG: %v", input.VEC, err.Error())
			continue
		}

		if subtle.ConstantTimeCompare(output[:len(plainText)], cipherText) != 1 {
			t.Errorf("VEC %s failed. CTX differs: %x != %x", input.VEC, output[:len(output)-16], cipherText)
			continue
		}
		if subtle.ConstantTimeCompare(output[len(plainText):], tag) != 1 {
			t.Errorf("VEC %s failed. TAG differs: %x != %x", input.VEC, output[len(plainText):], tag)
			continue
		}

		err = decryptFile(outputFileName, inputFileName, key, iv, aad)
		if err != nil {
			t.Errorf("VEC %s decryption failed: %v", input.VEC, err.Error())
			continue
		}

		decryptedInput, err := ioutil.ReadFile(inputFileName)
		if err != nil {
			t.Errorf("VEC %s failed. Failed to read decrypted input file: %v", input.VEC, err.Error())
			continue
		}

		if subtle.ConstantTimeCompare(decryptedInput, plainText) != 1 {
			t.Errorf("VEC %s failed. PTX differs: %x != %x", input.VEC, decryptedInput, plainText)
			continue
		}
	}
}
