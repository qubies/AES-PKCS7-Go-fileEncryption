package crypto

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"os"
	"testing"
)

func TestPadding(t *testing.T) {
	thingToPad := []byte("IAMWRONGLENGTH")
	//copy the slice
	initialPad := append([]byte(nil), thingToPad...)
	blockSize := 32
	Pad(blockSize, &thingToPad)
	if len(thingToPad) != blockSize {
		t.Errorf("Byte Length Incorrect after padding\nString:%s\nHex:%x", thingToPad, thingToPad)

	}
	//create a block of text that is all the blocksize chars.
	trickyPad := bytes.Repeat([]byte{byte(blockSize)}, blockSize)
	initialTricky := append([]byte(nil), trickyPad...)
	Pad(blockSize, &trickyPad)
	if len(trickyPad) != blockSize*2 {
		t.Errorf("Byte Length Incorrect on Tricky Pad\nString:%s\nHex:%x", thingToPad, thingToPad)

	}
	err := Unpad(&thingToPad)
	if err != nil {
		t.Errorf("Unpad on Inital Returned Error %s", err)
	}

	err = Unpad(&trickyPad)
	if err != nil {
		t.Errorf("Unpad on Tricky Returned Error %s", err)
	}
	if !bytes.Equal(trickyPad, initialTricky) {
		t.Errorf("Unpad Failed on Tricky Pad\nString:%s\nHex:%x", trickyPad, trickyPad)
	}

	if !bytes.Equal(thingToPad, initialPad) {
		t.Errorf("Unpad Failed on Inital Pad Pad\nString:%s\nHex:%x", thingToPad, thingToPad)

	}
	niler := []byte(nil)
	err = Unpad(&niler)
	if err == nil {
		t.Error("unpad did not error on nil input")
	}

}

func TestCrypto(t *testing.T) {
	w, err := os.Create("input")
	if err != nil {
		t.Errorf("File Creation Error: %s", err)
	}
	w.Write([]byte("crypt me"))
	key := []byte("secretkeylength1")
	iv, err := RandomBytes(aes.BlockSize)
	if err != nil {
		t.Errorf("encryptionError: %s", err)
	}

	err = EncryptFile("input", "crypted", key, iv)
	if err != nil {
		t.Errorf("encryptionError: %s", err)
	}

	err = DecryptFile("crypted", "output", key)
	if err != nil {
		t.Errorf("decryptionError: %s", err)
	}
	inputHash, err := Sha256FileSum("input")
	outputHash, err := Sha256FileSum("output")
	if err != nil {
		t.Errorf("Hashing Error: %s", err)
	}
	if bytes.Compare(inputHash, outputHash) != 0 {

		t.Error("pre->post encryption hashes do not match")
	}
	fmt.Printf(" Input Hash: %x\n", inputHash)
	fmt.Printf("Output Hash: %x\n", outputHash)

	cryString, err := EncryptString(key, []byte("Hello There"))
	if err != nil {
		t.Errorf("Error in String Encryption: %s", err)
	}
	decString, err := DecryptString(key, cryString)
	if err != nil {
		t.Errorf("Decryption Error: %s", err)
	}
	Unpad(&decString)
	if bytes.Compare(decString, []byte("Hello There")) != 0 {
		fmt.Printf("Decrypted String:%s\n", decString)
		fmt.Printf(" Expected String:%s\n", []byte("Hello There"))
		fmt.Printf("Decrypted String:%x\n", decString)
		fmt.Printf(" Expected String:%x\n", []byte("Hello There"))
		t.Error("Initial and final Strings do not match")
	}
}
