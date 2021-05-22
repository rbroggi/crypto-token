package main

import (
	"crypto-token/tkengine"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

type CCList []string

func main() {
	var ccs CCList
	flag.Var(&ccs, "i", "Comma-separated list of credit-cards")
	separator := flag.String("s", "|", "Separator for the table output")
	confFile := flag.String("c", "", "Engine configuration file path")
	flag.Parse()
	if len(ccs) == 0 {
		log.Fatal("Empty input")
		os.Exit(1)
	}

	tEngine, err := buildTKEngine(confFile)
	if err != nil {
		log.Fatalf("Error while creating dummy token engine, error %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("%s%s%s\n", "CC", *separator, "TK")

	for _, cc := range ccs {

		tk, err := tEngine.EncryptCC(cc)
		if err != nil {
			log.Fatalf("Could not Encrypt CC, error %v\n", err)
			os.Exit(3)
		}

		fmt.Printf("%s%s%s\n", cc, *separator, tk)

		cc2, err := tEngine.DecryptTK(tk)
		if err != nil {
			log.Fatalf("Could not Decrypt TK, error %v\n", err)
			os.Exit(4)
		}

		if cc != cc2 {
			log.Fatalf("Input CC %s different from decrypted CC %s", cc, cc2)
			os.Exit(5)
		}
	}

}


func buildTKEngine(confFile *string) (tkengine.TKEngine, error){
	var tEngine tkengine.TKEngine
	var err error
	if *confFile == "" {
		if tEngine, err = tkengine.NewDummyEngine(); err != nil {
			return nil, err
		}
	} else {
		conf, err := readConfigFile(*confFile)
		if err != nil {
			return nil, err
		}

		versioner, encKeysRepo, hmacKeysRepo, alphaProvider, err := parseConfig(conf)
		if err != nil {
			return nil, err
		}

		if tEngine, err = tkengine.NewEngine(versioner, encKeysRepo, hmacKeysRepo, alphaProvider); err != nil {
			return nil, err
		}
	}
	return tEngine, nil
}

func readConfigFile(path string) (*Config, error) {
	// Open our jsonFile
	jsonFile, err := os.Open(path)
	// if we os.Open returns an error then handle it
	if err != nil {
		return nil, err
	}
	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()

	// read our opened jsonFile as a byte array.
	byteValue, _ := ioutil.ReadAll(jsonFile)
	if err != nil {
		return nil, err
	}

	var c Config
	// we unmarshal our byteArray which contains our
	// jsonFile's content into 'c' which we defined above
	err = json.Unmarshal(byteValue, &c)
	if err != nil {
		return nil, err
	}

	return &c, nil
}

// ByteString is a byte array that serializes to hex
type ByteString []byte

// MarshalJSON serializes ByteArray to hex
func (s ByteString) MarshalJSON() ([]byte, error) {
	bytes, err := json.Marshal(fmt.Sprintf("%x", string(s)))
	return bytes, err
}

// UnmarshalJSON deserializes ByteArray to hex
func (s *ByteString) UnmarshalJSON(data []byte) error {
	var x string
	err := json.Unmarshal(data, &x)
	if err == nil {
		str, e := hex.DecodeString(x)
		*s = str
		err = e
	}

	return err

}

type Versioner struct {
	TokenizationVersion    string `json:"tokenizationVersion"`
	DetokenizationVersions string `json:"detokenizationVersions"`
}

func (v *Versioner) GetTokenizationVersion() (byte, error) {
	if v == nil {
		return 0, errors.New("nil Versioner")
	}
	if len(v.TokenizationVersion) != 1 {
		return 0, errors.New(fmt.Sprintf("Versioner should have a single-byte for tokenizationVersion, instead its %s", v.TokenizationVersion))
	}
	return []byte(v.TokenizationVersion)[0], nil
}

func (v *Versioner) GetDetokenizationVersions() ([]byte, error) {
	return []byte(v.DetokenizationVersions), nil
}

type Version struct {
	Vid           string     `json:"vid"`
	EncryptionKey ByteString `json:"encryptionKey"`
	HmacKey       ByteString `json:"hmacKey"`
}

type EncKeysRepo []Version
func (r *EncKeysRepo) GetKey(version byte) ([]byte, error) {
	if r == nil {
		return nil, errors.New("nil encryption key repo")
	}
	for _, ver := range *r {
		if string(version) == ver.Vid {
			return ver.EncryptionKey, nil
		}
	}

	return nil, errors.New(fmt.Sprintf("Version %s not found in repo", string(version)))
}

type HmacKeysRepo []Version
func (r *HmacKeysRepo) GetKey(version byte) ([]byte, error) {
	if r == nil {
		return nil, errors.New("nil encryption key repo")
	}
	for _, ver := range *r {
		if string(version) == ver.Vid {
			return ver.HmacKey, nil
		}
	}

	return nil, errors.New(fmt.Sprintf("Version %s not found in repo", string(version)))
}

type Config struct {
	Versioner Versioner         `json:"versioner"`
	Versions  []Version         `json:"versions"`
	CharSets  map[string]string `json:"charSets"`
}
type alphaProvider map[string]string

func (a *alphaProvider) GetAlphabetForBase(base uint32) ([]byte, error) {
	if a == nil {
		return nil, errors.New("nil CharSets provider")
	}
	alpha, ok := (*a)[fmt.Sprint(base)]
	if !ok {
		return nil, errors.New(fmt.Sprintf("no available Version %d", base))
	}
	return []byte(alpha), nil
}

func parseConfig(c *Config) (tkengine.KeyVersioner, tkengine.KeyRepo, tkengine.KeyRepo, tkengine.AlphabetProvider, error) {
	if c == nil {
		return nil, nil, nil, nil, errors.New("nil Config")
	}
	// return error if write Version is more than one byte
	if _, err := c.Versioner.GetTokenizationVersion(); err != nil {
		return nil, nil, nil, nil, err
	}

	var encRepo EncKeysRepo
	encRepo = c.Versions

	var hmacRepo HmacKeysRepo
	hmacRepo = c.Versions

	var alphaP alphaProvider
	alphaP = c.CharSets

	// sanity check - verify that all the tokenization Version is available in  both repositories
	tokVer, err := c.Versioner.GetTokenizationVersion()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if _, err := encRepo.GetKey(tokVer); err != nil {
		return nil, nil, nil, nil, err
	}
	if _, err := hmacRepo.GetKey(tokVer); err != nil {
		return nil, nil, nil, nil, err
	}

	// sanity check - verify that all the de-tokenization Versions are available in  both repositories
	detokVer, err := c.Versioner.GetDetokenizationVersions()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	for _,dver := range detokVer {
		if _, err := encRepo.GetKey(dver); err != nil {
			return nil, nil, nil, nil, err
		}
		if _, err := hmacRepo.GetKey(dver); err != nil {
			return nil, nil, nil, nil, err
		}
	}

	// sanity-check for alpha can be delegated to the NewEngine method therefore we do not check it here

	return &c.Versioner, &encRepo, &hmacRepo, &alphaP, nil
}

// Set is the method to set the flag value, part of the flag.Value interface.
// Set's argument is a string to be parsed to set the flag.
// It's a comma-separated list, so we split it.
func (l *CCList) Set(value string) error {
	// If we wanted to allow the flag to be set multiple times,
	// accumulating values, we would delete this if statement.
	// That would permit usages such as
	//	-i 4444333322221111 -i 4444333322221112
	// and other combinations.
	if len(*l) > 0 {
		return errors.New("CCList flag already set")
	}
	for _, cc := range strings.Split(value, ",") {
		*l = append(*l, strings.TrimSpace(cc))
	}
	return nil
}

// String is the method to format the flag's value, part of the flag.Value interface.
// The String method's output will be used in diagnostics.
func (l *CCList) String() string {
	return fmt.Sprintf("%v", *l)
}
