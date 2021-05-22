package tkengine

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/capitalone/fpe/ff1"
	"math"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// TKEngine is a tokenization engine which regulates
// encryption of credit cards and decryption of tokens
type TKEngine interface {
	// EncryptCC takes a valid CC in input which has
	// (13,19] characters and output a Token or an error
	// encoding is supposed to be [0-9] chars in CC in ascii
	// so each character need to be a byte
	// Error types: InvalidCC format
	EncryptCC(cc string) (string, error)
	// DecryptTK takes a valid TK in input which has
	// (13,19] characters and output the decrypted CC or an error
	// encoding is supposed to be [a-z0-9A-Z] chars in CC in ascii
	// so each character need to be a byte
	// Error types: InvalidTK format
	DecryptTK(tk string) (string, error)
}

// NewEngine returns a tokenization engine with custom versioner, encryption keys repositories and alphabet providers
func NewEngine(versioner KeyVersioner, encryptionKeys KeyRepo, hmacKeys KeyRepo, alphaProvider AlphabetProvider) (TKEngine, error) {
	// Validate alpha-provider
	if err := validateAlphabetProvider(alphaProvider); err != nil {
		return nil, err
	}
	return &engine{
		versioner:      versioner,
		encryptionKeys: encryptionKeys,
		hmacKeys:       hmacKeys,
		alphaProvider:  alphaProvider,
	}, nil
}

func validateAlphabetProvider(alphaProvider AlphabetProvider) error {
	for _, i := range []uint32{14, 15, 16, 18, 22, 32} {
		alpha, err := alphaProvider.GetAlphabetForBase(i)
		if err != nil {
			return errors.New(fmt.Sprintf("Error while retriving alphabet for base %d: %v", len(alpha), err))
		}
		if len(alpha) != int(i) {
			return errors.New(fmt.Sprintf("Got alphabet size %d for base %d. Size should match base", len(alpha), i))
		}
		uniqueSymbols := make(map[byte]struct{}, i)
		for _, symbol := range alpha {
			uniqueSymbols[symbol] = struct{}{}
		}
		if len(uniqueSymbols) != len(alpha) {
			return errors.New(fmt.Sprintf("alphabet for base %d contains duplicated elements [%v]", i, alpha))
		}
	}
	return nil
}

// NewEngineWithDefaultAlphabet returns a TKEngine which relies on the versioner,
// the encryption keys repository and the hmac keys repository passed in input
func NewEngineWithDefaultAlphabet(versioner KeyVersioner, encryptionKeys KeyRepo, hmacKeys KeyRepo) TKEngine {
	return &engine{
		versioner:      versioner,
		encryptionKeys: encryptionKeys,
		hmacKeys:       hmacKeys,
		alphaProvider:  DefaultAlphabetProvider{},
	}
}

// NewDummyEngine returns a TKEngine for tokenization and detokenization
// versioning and implementation are hidden from users
func NewDummyEngine() (TKEngine, error) {
	// hard-coded encryption keys will have to change
	encryptionKeys := []string{
		"2B7E151628AED2A6ABF7158809CF4F3C",
		"2C7E151628AED2A6ABF7158809CF4F3B",
		"2D7E151628AED2A6ABF7158809CF4F31",
		"2E7E151628AED2A6ABF7158809CF4E3B",
	}

	// hard-coded hmac keys will have to change
	hmacKeys := []string{
		"3B7E151628AED2A6ABF7158809CF4F3C",
		"3C7E151628AED2A6ABF7158809CF4F3B",
		"3D7E151628AED2A6ABF7158809CF4F31",
		"3E7E151628AED2A6ABF7158809CF4E3B",
	}

	if len(encryptionKeys) != len(hmacKeys) {
		return nil, errors.New(fmt.Sprintf("Encryption Keys and Hmac keys maps should have the same size, instead they have respectively: [%d, %d]", len(encryptionKeys), len(hmacKeys)))
	}

	eKeys := make(map[byte][]byte, len(encryptionKeys))
	hKeys := make(map[byte][]byte, len(hmacKeys))
	ver := byte('a')
	for i, k := range encryptionKeys {
		ekey, err := hex.DecodeString(k)
		if err != nil {
			return nil, err
		}
		eKeys[ver] = ekey
		hkey, err := hex.DecodeString(hmacKeys[i])
		if err != nil {
			return nil, err
		}
		hKeys[ver] = hkey
		ver += 1
	}

	// building engine
	e := engine{
		encryptionKeys: &keyRepo{
			keys: eKeys,
		},
		hmacKeys: &keyRepo{
			keys: hKeys,
		},
		versioner:     dummyVersioner{}, // use dummy versioner
		alphaProvider: DefaultAlphabetProvider{},
	}

	return &e, nil
}

// KeyRepo is a key repository which provides a container
// for crypto keys. The repository indexes keys by version
// to enable dynamic key-rotation strategies
type KeyRepo interface {
	// GetKey returns a key for the input version
	// an error is issued if the key is not present in
	// the repo
	GetKey(version byte) ([]byte, error)
}

// KeyVersioner is responsible for determining at each point in time
// which version is to be used for 'Tokenization'
// and which versions can be used for 'Detokenization'
type KeyVersioner interface {
	// GetTokenizationVersion returns the current key used for 'Tokenization' operation
	GetTokenizationVersion() (byte, error)
	// GetDetokenizationVersions returns the current keys allowed for 'Detokenization' operation
	GetDetokenizationVersions() ([]byte, error)
}

// AlphabetProvider is a provider regulating which alphabet
// to use for encoding in different bases
type AlphabetProvider interface {
	// GetAlphabetForBase return an alphabet of distinct characters (here represented by bytes)
	// of size equal to the input 'base'. Each letter symbol in the []byte array will be used
	// to represent a multiplier in the provided base.
	// An example would be to have an Hex alphabet:
	// Hex is a base 16 with associated alphabet equal to []byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}
	// analogously one can define different alphabets for different bases:
	// base 5 can be used with alphabet []byte{'a', 'e', 'i', 'o', 'u'}
	GetAlphabetForBase(base uint32) ([]byte, error)
}

type engine struct {
	versioner      KeyVersioner
	encryptionKeys KeyRepo
	hmacKeys       KeyRepo
	alphaProvider  AlphabetProvider
}

// EncryptCC encrypts a credit card input and return the corresponding token. The token format preserves the
// first 6 digits and the last 4 digits of the credit card and replaces the middle digits by a series of alpha
// characters.
// the method will:
// 1. will validate it's input cc against regex ([0-9]{13,19})
// 2. randomly select one of it's inside versions to encrypt the cc (this is only to simulate the time effect)
// 3. with the 6x4 of the card it will generate a tweak by hashing it
// 4. with the tweak and the key linked to the version it will encrypt the cc middle-digits using a format preserving
//    encryption mechanism ff1.
// 5. will encode the following info into the token:
//    a. The version byte (in the 7th char)
//    b. The encrypted payload in base_x ( where x will be a function of the total size of the card)
func (e *engine) EncryptCC(cc string) (string, error) {
	// input validation
	if !isValidCC(cc) {
		return "", errors.New(fmt.Sprintf("Invalid CC format"))
	}

	ccBytes := []byte(cc)

	// 6x4
	sixByFour := make([]byte, 10)
	copy(sixByFour, ccBytes[:6])
	sixByFour = append(sixByFour, ccBytes[len(ccBytes)-4:]...)

	// middle-digits
	md := cc[6 : len(cc)-4]

	// retrieve write-version
	v, err := e.versioner.GetTokenizationVersion()
	if err != nil {
		return "", err
	}

	// get encryption and hmac keys
	ekey, err := e.encryptionKeys.GetKey(v)
	if err != nil {
		return "", err
	}
	hkey, err := e.hmacKeys.GetKey(v)
	if err != nil {
		return "", err
	}

	// generating the hmac from 6x4 and retrieving the tweak
	h := hmac.New(sha256.New, hkey)
	h.Write(sixByFour)
	tweak := h.Sum(nil)

	// format preserving encryption cipher
	cipher, err := ff1.NewCipher(10, len(tweak), ekey, tweak)
	if err != nil {
		return "", err
	}

	// FPE
	ciphertext, err := cipher.Encrypt(md)
	if err != nil {
		return "", err
	}

	// FPE property - should preserve length
	if len(md) != len(ciphertext) {
		return "", errors.New(fmt.Sprintf("middle digits [%s] and ciphertext [%s] length differs", md, ciphertext))
	}

	// encoding TkMD will generate an alpha-num token with one char less than the ciphertext
	// this allows to accommodate also the version char in the token
	tkmd, err := encodeTkMD(ciphertext, e.alphaProvider)
	if err != nil {
		return "", err
	}

	// concatenate: 6 first cc digits || version char || encoded middle digits TK || 4 last cc digits
	return fmt.Sprintf("%s%s%s%s", cc[0:6], string(v), tkmd, cc[len(cc)-4:]), nil
}

func contains(s []byte, v byte) bool {
	for _, el := range s {
		if v == el {
			return true
		}
	}
	return false
}

// DecryptTK decrypts a token into it's original credit-card.
// the method will:
// 1. validate the TK input - depending on the size of the token a different base is used to encode the middle-digits
// 2. retrieve the version char (or byte) (char number 7)
// 3. with the 6x4 of the token we will generate a tweak by "hmac-ing" it
// 4. decode the middle-digits into its decimal string representation
// 5. with the tweak and the encryption key linked to the version we will decrypt the decimal string cipher
func (e *engine) DecryptTK(tk string) (string, error) {

	detokVers, err := e.versioner.GetDetokenizationVersions()
	if err != nil {
		return "", err
	}

	// input validation
	if !isValidTK(tk, e.alphaProvider, detokVers) {
		return "", errors.New(fmt.Sprintf("Invalid TK format"))
	}

	tkBytes := []byte(tk)

	// 6x4
	sixByFour := make([]byte, 10)
	copy(sixByFour, tkBytes[:6])
	sixByFour = append(sixByFour, tkBytes[len(tkBytes)-4:]...)

	// get token version
	v := tk[6]

	// get encryption and hmac keys
	ekey, err := e.encryptionKeys.GetKey(v)
	if err != nil {
		return "", err
	}
	hkey, err := e.hmacKeys.GetKey(v)
	if err != nil {
		return "", err
	}

	// Parsing middle-digits
	md := tk[6 : len(tk)-4]

	// generating the hmac from 6x4 and retrieving the tweak
	h := hmac.New(sha256.New, hkey)
	h.Write(sixByFour)
	tweak := h.Sum(nil)

	// decode middle-digits into decimal string representation
	decmd, err := decodeTkMD(md[1:], e.alphaProvider)
	if err != nil {
		return "", err
	}

	// format preserving encryption cipher
	cipher, err := ff1.NewCipher(10, len(tweak), ekey, tweak)
	if err != nil {
		return "", err
	}

	// FPE decryption
	plaintext, err := cipher.Decrypt(decmd)
	if err != nil {
		return "", err
	}

	// FPE property
	if len(md) != len(plaintext) {
		return "", errors.New(fmt.Sprintf("middle digits [%s] and plaintext [%s] length differs", md, plaintext))
	}

	// concatenate: 6 first cc digits || version char || encoded middle digits TK || 4 last cc digits
	return fmt.Sprintf("%s%s%s", tk[0:6], plaintext, tk[len(tk)-4:]), nil
}

// keyRepo simulates a key repository. In the real implementation
// this will be stored an a safe vault or in a DB document. It will be distributed across
// different datacenters offline in advance. For the sake of simplification
// here we use a map between a byte (version) and a []byte (key)
type keyRepo struct {
	// keys is a map between a given
	// version (represented by a byte) and an
	// key (represented by a byte slice)
	keys map[byte][]byte
}

// GetKey returns a key for a given version v or an error if there is no key in the repository
// for the specified version
func (r *keyRepo) GetKey(v byte) ([]byte, error) {
	key, ok := r.keys[v]
	if !ok {
		return nil, errors.New(fmt.Sprintf("No key exists for version %v", v))
	}
	return key, nil
}

type dummyVersioner struct{}

// GetTokenizationVersion randomly selects a version from a to d
func (verser dummyVersioner) GetTokenizationVersion() (byte, error) {
	rand.Seed(time.Now().UnixNano())
	// hardcoded versions
	vers := []byte{'a', 'b', 'c', 'd'}
	if len(vers) == 0 {
		return 0, errors.New(fmt.Sprintf("Key repo contains no key"))
	}
	v := vers[rand.Intn(len(vers))]
	return v, nil
}

// GetDetokenizationVersions statically returns the versions 'a', 'b', 'c' and 'd'
func (verser dummyVersioner) GetDetokenizationVersions() ([]byte, error) {
	return []byte{'a', 'b', 'c', 'd'}, nil
}

// GetWriteVersion return the current write version
// here we simulate it by randomly picking up one of
// the available versions, in the real implementation
// this will be driven by time
func (r *keyRepo) GetWriteVersion() (byte, error) {
	vers := make([]byte, 0, len(r.keys))
	for k := range r.keys {
		vers = append(vers, k)
	}
	if len(vers) == 0 {
		return 0, errors.New(fmt.Sprintf("Key repo contains no key"))
	}
	v := vers[rand.Intn(len(vers))]
	return v, nil
}

// encodingBaseToSaveOneChar get's in input the size of the CC or TK
// and return the base in which the encoding must be done
// s should be in {13, 19} range otherwise an error is returned
func encodingBaseToSaveOneChar(s int) (uint32, error) {
	if s < 3 || s > 9 {
		return 0, errors.New(fmt.Sprintf("Invalid CC or TK size: %d", s))
	}

	m := map[uint32]uint32{
		uint32(3): uint32(32), // 32 is the first x so that x^2 > 999
		uint32(4): uint32(22), // 22 is the first x so that x^3 > 9999
		uint32(5): uint32(18), // 18 is the first x so that x^4 > 99999
		uint32(6): uint32(16), // 16 is the first x so that x^5 > 999999
		uint32(7): uint32(15), // 15 is the first x so that x^6 > 9999999
		uint32(8): uint32(14), // 14 is the first x so that x^7 > 99999999
		uint32(9): uint32(14), // 14 is the first x so that x^8 > 999999999
	}

	return m[uint32(s)], nil
}

// bitsRequired return the least amount of bits
// for representing a given number
func bitsRequired(n uint32) uint32 {
	return uint32(math.Ceil(math.Log2(float64(n))))
}

// DefaultAlphabetProvider provides a default value for alphabet provider
type DefaultAlphabetProvider struct{}

// GetAlphabetForBase return the alphabet for the bases
// 14, 15, 16, 18, 22, 32
// anything different than those numbers will be considered an error
func (d DefaultAlphabetProvider) GetAlphabetForBase(base uint32) ([]byte, error) {
	b := map[uint32][]byte{
		uint32(14): {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n'},
		uint32(15): {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o'},
		uint32(16): {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'},
		uint32(18): {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r'},
		uint32(22): {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v'},
		uint32(32): {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5'},
	}

	alphabet, ok := b[base]
	if !ok {
		return []byte{}, errors.New(fmt.Sprintf("No availlable alphabet for base %d", base))
	}

	return alphabet, nil
}

// decodeTkMD takes in input a string that contains only the valid alphabet chars
// and returns the equivalent digit string (0-9) whith exactly one more character
// than the input tkMD. tkMD input must respect the size of the given token which is
// [2, 18]
func decodeTkMD(tkMD string, aphaProvider AlphabetProvider) (string, error) {
	if len(tkMD) < 2 || len(tkMD) > 8 {
		return "", errors.New(fmt.Sprintf("tk middle digits len is not in interval [2, 8]. Instead it is %d", len(tkMD)))
	}

	decodeds := len(tkMD) + 1

	// retrieve the base for the encoded token
	base, err := encodingBaseToSaveOneChar(decodeds)
	if err != nil {
		return "", err
	}

	// retrieve the alphabet for the encoding base
	alpha, err := aphaProvider.GetAlphabetForBase(base)
	if err != nil {
		return "", err
	}

	// build the alpha map for fast translation between byte and index
	alphaMap := make(map[byte]int, len(alpha))
	for i, el := range alpha {
		alphaMap[el] = i
	}

	var n uint32 = 0
	for i, b := range []byte(tkMD) {
		m, ok := alphaMap[b]
		if !ok {
			return "", errors.New(fmt.Sprintf("Found char in token that does not belong to the alphabet: char %s ( byte %d)", string(b), b))
		}
		n = n + (uint32(m) * uint32(math.Pow(float64(base), float64(len(tkMD)-1-i))))
	}
	str := strconv.Itoa(int(n))
	var strb strings.Builder
	strb.Grow(decodeds)
	for i := 0; i < decodeds-len(str); i++ {
		_, err := fmt.Fprintf(&strb, "%s", "0")
		if err != nil {
			return "", err
		}
	}
	strb.WriteString(str)
	return strb.String(), nil
}

// encodeTkMD takes in input a string that contains only digits (0-9)
// and returns an alpha-num encoding in a base that allows to represent
// it using one less character than in input
func encodeTkMD(ciphertext string, alphaProvider AlphabetProvider) (string, error) {
	if len(ciphertext) < 3 || len(ciphertext) > 9 {
		return "", errors.New(fmt.Sprintf("ciphertext len is not in interval [3, 9]. Instead it is %d", len(ciphertext)))
	}

	// parsing ciphertext into a number
	n, err := strconv.ParseUint(ciphertext, 10, 32)
	if err != nil {
		return "", err
	}

	// retrieve the encoding base for the specific ciphertext
	base, err := encodingBaseToSaveOneChar(len(ciphertext))
	if err != nil {
		return "", err
	}

	// retrieve the alphabet for the encoding base
	alpha, err := alphaProvider.GetAlphabetForBase(base)
	if err != nil {
		return "", err
	}

	fsize := len(ciphertext) - 1
	var strb strings.Builder
	strb.Grow(fsize)
	for i := 1; i < fsize+1; i++ {
		m := uint32(int32(n) / int32(math.Pow(float64(base), float64(fsize-i))))
		n = uint64(int32(n) % int32(math.Pow(float64(base), float64(fsize-i))))
		_, err := fmt.Fprintf(&strb, "%s", string(alpha[m]))
		if err != nil {
			return "", err
		}
	}

	return strb.String(), nil
}

// isValidCC returns true if string matches regex [0-9]{13,19}
func isValidCC(cc string) bool {
	// in real program might be worth considering having global/static regex
	// and not build it each time
	ccRe := regexp.MustCompile(`^[0-9]{13,19}$`)
	return ccRe.Match([]byte(cc))
}

// isValidCC returns true if string matches token structure
func isValidTK(tk string, alphaProvider AlphabetProvider, vers []byte) bool {
	if len(tk) < 13 || len(tk) > 19 {
		return false
	}
	// six first digits
	six := tk[:6]
	for _, el := range six {
		if !unicode.IsDigit(el) {
			return false
		}
	}

	// for last digits
	four := tk[len(tk)-4:]
	for _, el := range four {
		if !unicode.IsDigit(el) {
			return false
		}
	}

	// retrieve the encoding base for the specific ciphertext
	base, err := encodingBaseToSaveOneChar(len(tk) - 10)
	if err != nil {
		return false
	}

	// retrieve the alphabet for the encoding base
	alpha, err := alphaProvider.GetAlphabetForBase(base)
	if err != nil {
		return false
	}

	// build the alpha map
	alphaMap := make(map[byte]int, len(alpha))
	for i, el := range alpha {
		alphaMap[el] = i
	}

	// middle digits belong to alphabet in this base
	middle := tk[7 : len(tk)-4]
	for _, el := range middle {
		_, ok := alphaMap[byte(el)]
		if !ok {
			return false
		}
	}

	// check in versioner if the key belong to the current 'Detokenization' keys
	if !contains(vers, tk[6]) {
		return false
	}

	return true
}