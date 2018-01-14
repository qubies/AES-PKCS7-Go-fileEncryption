# Package crypto
This package contains some simple crypto examples and functions written in go. 
I have made attempts to ensure thier correctness, however use at your own risk.

## INSTALLATION
go get github.com/qubies/AES-PKCS7-Go-fileEncryption
### PACKAGE DOCUMENTATION

#### package simpleCrypto
    import "github.com/qubies/AES-PKCS7-Go-fileEncryption/simpleCrypto"


## FUNCTIONS

#### func DecryptFile(srcfile, dstfile string, key []byte) error
    DecryptFile decrypts srcfile into dstfile using key. keylength must be
    16 bytes. modified from https://talks.golang.org/2010/io/decrypt.go

#### func DecryptString(key, ciphertext []byte) ([]byte, error)
    DecryptString takes a key and ciphertext generated from Encrypt string
    and returns just the plain text.

#### func EncryptFile(srcfile, dstfile string, key []byte) error
    Encrypt file will create an encrypted copy of srcfile at dstfile.
    appends a randomized IV to the end of the file for decryption. use of
    EncryptFile should be combined with a hash for verification. Key length
    must be 16 bytes modified from
    https://talks.golang.org/2010/io/decrypt.go

#### func EncryptString(key, plain []byte) ([]byte, error)
    EncryptString takes a byte array and a 16 byte key to return an
    encrypted byte array. The resultant byte array is actually:

	IV + HMAC + Ciphertext

    WARNING: EncryptString may return plaintext on error. Check your errors.

#### func Pad(blockSize int, input *[]byte) error
    Pad applies PKCS7 padding in place to a byte array. Padding is necessary
    to ensure plain text input is divisible by the encryption block size.

#### func RandomBytes(len int) ([]byte, error)
    RandomBytes returns a byte array of len of cryptographically secure
    random bytes.

#### func Sha256FileSum(srcfile string) ([]byte, error)
    Sha256FileSum returns the sha256 digest of a file as a byte array.

#### func Unpad(input *[]byte) error
    Unpad removes PKCS7 padding from byte array in place.


