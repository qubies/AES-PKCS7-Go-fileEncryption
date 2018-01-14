package crypto

import (
	"bytes"
	"fmt"
	"os"
	"testing"
)

func TestPadding(t *testing.T) {
	// a simple test
	thingToPad := []byte("IAMWRONGLENGTH")

	//copy the slice
	initialPad := append([]byte(nil), thingToPad...)

	//a wierd size
	blockSize := 32

	Pad(blockSize, &thingToPad)

	// since the original was less than blocksize, we should now have a single block.
	if len(thingToPad) != blockSize {
		t.Errorf("Byte Length Incorrect after padding\nString:%s\nHex:%x",
			thingToPad, thingToPad)
	}

	// a tricky test
	// create a block of text that is all the blocksize chars.
	trickyPad := bytes.Repeat([]byte{byte(blockSize)}, blockSize)
	initialTricky := append([]byte(nil), trickyPad...)

	Pad(blockSize, &trickyPad)

	// this block was originally exactly a block size, made out of blocksize bytes.
	// now it should be doubled.
	if len(trickyPad) != blockSize*2 {
		t.Errorf("Byte Length Incorrect on Tricky Pad\nString:%s\nHex:%x",
			thingToPad, thingToPad)
	}

	//check Unpad
	err := Unpad(&thingToPad)
	if err != nil {
		t.Errorf("Unpad on Inital Returned Error %s", err)
	}

	//unpad trickyPad
	err = Unpad(&trickyPad)
	if err != nil {
		t.Errorf("Unpad on Tricky Returned Error %s", err)
	}

	//check if the original simple case has been unpadded.
	if !bytes.Equal(thingToPad, initialPad) {
		t.Errorf("Unpad Failed on Inital Pad Pad\nString:%s\nHex:%x", thingToPad, thingToPad)

	}

	// check if the unpadded tricky is the same as it was
	if !bytes.Equal(trickyPad, initialTricky) {
		t.Errorf("Unpad Failed on Tricky Pad\nString:%s\nHex:%x", trickyPad, trickyPad)
	}

	//check behaviour with a nil string
	niler := []byte(nil)
	err = Unpad(&niler)
	if err == nil {
		t.Error("unpad did not error on nil input")
	}
}

func TestCrypto(t *testing.T) {
	// create an input file for testing
	w, err := os.Create("input")
	if err != nil {
		t.Errorf("File Creation Error: %s", err)
	}
	w.Write([]byte("crypt me"))

	// set our key value... shh don't tell anyone!
	key := []byte("secretkeylength1")

	// encrypt the input file to crypted.
	err = EncryptFile("input", "crypted", key)
	if err != nil {
		t.Errorf("encryptionError: %s", err)
	}

	// decrypt crypted to output
	err = DecryptFile("crypted", "output", key)
	if err != nil {
		t.Errorf("decryptionError: %s", err)
	}

	// generate a sha256 hash of input and output
	inputHash, err := Sha256FileSum("input")
	if err != nil {
		t.Errorf("Hashing Error: %s", err)
	}

	outputHash, err := Sha256FileSum("output")
	if err != nil {
		t.Errorf("Hashing Error: %s", err)
	}

	// the 2 hash values should be identical
	if !bytes.Equal(inputHash, outputHash) {
		fmt.Printf(" Input Hash: %x\n", inputHash)
		fmt.Printf("Output Hash: %x\n", outputHash)
		t.Error("pre->post encryption hashes do not match")
	}

	// test string encryption
	// encrypt "Hello There"
	cryString, err := EncryptString(key, []byte("Hello There"))
	if err != nil {
		t.Errorf("Error in String Encryption: %s", err)
	}

	// decrypt Hello There
	decString, err := DecryptString(key, cryString)
	if err != nil {
		t.Errorf("Decryption Error: %s", err)
	}

	//unpad it
	err = Unpad(&decString)
	if err != nil {
		t.Errorf("Unpad Error: %s", err)
	}

	//check if the decrypted value is equal to the input
	if !bytes.Equal(decString, []byte("Hello There")) {
		fmt.Printf("Decrypted String:%s\n", decString)
		fmt.Printf(" Expected String:%s\n", []byte("Hello There"))
		fmt.Printf("Decrypted String:%x\n", decString)
		fmt.Printf(" Expected String:%x\n", []byte("Hello There"))
		t.Error("Initial and final Strings do not match")
	}
}
