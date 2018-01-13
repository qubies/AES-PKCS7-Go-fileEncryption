package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
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
	if iLen < 1 {
		return errors.New("Unpad called on zero length byte array")
	}
	padded := int((*input)[iLen-1])
	for x := 1; x <= padded && x <= iLen; x++ {
		if int((*input)[iLen-x]) != padded {
			return errors.New("Invalid Padding Char Found")
		}
	}
	*input = (*input)[:(iLen - padded)]
	return nil
}

func encrypt(key, plain []byte) {
	key = []byte("example key 1234")
	plain = []byte("exampleplaintext")

	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. For an example of such padding, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. Here we'll
	// assume that the plaintext is already of the correct length.
	if len(plain)%aes.BlockSize != 0 {
		panic("plaintext is not a multiple of the block size")
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
}
