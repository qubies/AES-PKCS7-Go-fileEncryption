package crypto

import (
	"bytes"
	//"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
	"os"
)

func pad(blockSize int, input *[]byte) error {
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

func unpad(input *[]byte) error {
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

//modified from https://talks.golang.org/2010/io/decrypt.go
func encryptFile(srcfile, dstfile string, key, iv []byte) error {
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
func decryptFile(srcfile, dstfile string, key []byte) error {
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

/*func encrypt(key, plain []byte) ([]byte, error) {

	err := pad(aes.BlockSize, plain)
	if err != nil {
		return plain, err
	}
	//check padding is correct
	if len(plain)%aes.BlockSize != 0 {
		return plain, errors.New("plaintext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plain))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plain)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.

	fmt.Printf("%x\n", ciphertext)
}*/
