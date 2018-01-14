package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"os"
)

func Pad(blockSize int, input *[]byte) error {
	//the padding is the length of padding added
	iLen := len(*input)
	//so the blocksize - the leftover is the amount we have to add
	//if the blocksize fits perfectly, we add a full block of padding ie 0x32 * 32
	pLen := blockSize - (iLen % blockSize)
	//build the padding text
	padding := bytes.Repeat([]byte{byte(pLen)}, pLen)
	//add it to the initial string
	*input = append(*input, padding...)
	return nil
}

func Unpad(input *[]byte) error {
	iLen := len(*input)
	//empty.. no good
	if iLen < 1 {
		return errors.New("Unpad called on zero length byte array")
	}
	//this is the char added
	padded := int((*input)[iLen-1])
	//check if all the removeable chars are good to remove
	for x := 1; x <= padded && x <= iLen; x++ {
		if int((*input)[iLen-x]) != padded {
			return errors.New("Invalid Padding Char Found")
		}
	}
	//cut them off
	*input = (*input)[:(iLen - padded)]
	return nil
}
func RandomBytes(len int) ([]byte, error) {
	ret := make([]byte, len)
	_, err := rand.Read(ret)
	return ret, err
}

func Sha256FileSum(srcfile string) ([]byte, error) {
	var ret []byte
	f, err := os.Open(srcfile)
	if err != nil {
		return ret, err
	}
	defer f.Close()

	h := sha256.New()

	if _, err := io.Copy(h, f); err != nil {
		return ret, err
	}
	ret = h.Sum(nil)
	return ret, nil
}

//modified from https://talks.golang.org/2010/io/decrypt.go
//appends the IV to the end of the file for decryption
func EncryptFile(srcfile, dstfile string, key, iv []byte) error {
	// open the source
	r, err := os.Open(srcfile)
	if err != nil {
		return err
	}
	// create the destination
	var w io.WriteCloser
	w, err = os.Create(dstfile)
	if err != nil {
		return err
	}
	defer w.Close()

	//create the cipher
	c, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	//stream the file into the cypher using output feedback mode, for streaming
	_, err = io.Copy(cipher.StreamWriter{S: cipher.NewOFB(c, iv), W: w}, r)
	//write the IV to the end of the file.
	w.Write(iv)
	return err
}

//modified from https://talks.golang.org/2010/io/decrypt.go
func DecryptFile(srcfile, dstfile string, key []byte) error {
	f, err := os.Open(srcfile)
	if err != nil {
		return err
	}
	defer f.Close()
	//read the iv from the file
	iv := make([]byte, aes.BlockSize)
	stat, err := os.Stat(srcfile)
	start := stat.Size() - aes.BlockSize
	_, err = f.ReadAt(iv, start)
	if err != nil {
		return err
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	r := cipher.StreamReader{S: cipher.NewOFB(c, iv), R: f}
	w, err := os.Create(dstfile)
	if err != nil {
		return err
	}
	defer w.Close()
	_, err = io.Copy(w, r)
	os.Truncate(dstfile, stat.Size()-aes.BlockSize)
	return err
}

//returns plaintext on error. check your errors.
func EncryptString(key, plain []byte) ([]byte, error) {

	err := Pad(aes.BlockSize, &plain)
	if err != nil {
		return plain, err
	}
	//check padding is correct
	if len(plain)%aes.BlockSize != 0 {
		return plain, errors.New("plaintext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return plain, err
	}

	//the finished ciphertext is actually
	// IV + SHA256mac + ciphertext
	ciphertext := make([]byte, aes.BlockSize+len(plain)+sha256.Size)
	iv := ciphertext[:aes.BlockSize]
	mac := ciphertext[aes.BlockSize : aes.BlockSize+sha256.Size]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	rawMac := hmac.New(sha256.New, key)
	rawMac.Write(plain)
	copy(mac, rawMac.Sum(nil))

	mode := cipher.NewCBCEncrypter(block, iv)

	mode.CryptBlocks(ciphertext[aes.BlockSize+sha256.Size:], plain)

	return ciphertext, nil
}

// decrypts a string
func DecryptString(key, ciphertext []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return ciphertext, errors.New("unable to create cipher")
	}

	if len(ciphertext) < aes.BlockSize {
		return ciphertext, errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	mac := ciphertext[aes.BlockSize : aes.BlockSize+sha256.Size]
	ciphertext = ciphertext[aes.BlockSize+sha256.Size:]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		return ciphertext, errors.New("ciphertext broken or corrupted")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)

	rawMac := hmac.New(sha256.New, key)
	rawMac.Write(ciphertext)
	if !hmac.Equal(rawMac.Sum(nil), mac) {
		return ciphertext, errors.New("HMAC Failure, Message Corrupted")
	}

	return ciphertext, nil
}
