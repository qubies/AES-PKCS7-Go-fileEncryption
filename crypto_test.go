package crypto

import (
	"bytes"
	"testing"
)

func TestPadding(t *testing.T) {
	thingToPad := []byte("IAMWRONGLENGTH")
	//copy the slice
	initialPad := append([]byte(nil), thingToPad...)
	blockSize := 32
	pad(blockSize, &thingToPad)
	if len(thingToPad) != blockSize {
		t.Errorf("Byte Length Incorrect after padding\nString:%s\nHex:%x", thingToPad, thingToPad)

	}
	//create a block of text that is all the blocksize chars.
	trickyPad := bytes.Repeat([]byte{byte(blockSize)}, blockSize)
	initialTricky := append([]byte(nil), trickyPad...)
	pad(blockSize, &trickyPad)
	if len(trickyPad) != blockSize*2 {
		t.Errorf("Byte Length Incorrect on Tricky Pad\nString:%s\nHex:%x", thingToPad, thingToPad)

	}
	err := unpad(&thingToPad)
	if err != nil {
		t.Errorf("Unpad on Inital Returned Error %s", err)
	}

	err = unpad(&trickyPad)
	if err != nil {
		t.Errorf("Unpad on Tricky Returned Error %s", err)
	}
	if !bytes.Equal(trickyPad, initialTricky) {
		t.Errorf("Unpad Failed on Tricky Pad\nString:%s\nHex:%x", trickyPad, trickyPad)
	}

	if !bytes.Equal(thingToPad, initialPad) {
		t.Errorf("Unpad Failed on Inital Pad Pad\nString:%s\nHex:%x", thingToPad, thingToPad)

	}

}

func TestCrypto(t *testing.T) {
	t.Error("Not Yet Implemented")
}
