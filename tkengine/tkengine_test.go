package tkengine

import (
	"errors"
	"fmt"
	"testing"
)

type deterministicVersioner struct {
	tokError      bool
	detokError    bool
	tokVersion    byte
	detokVersions []byte
}

func (d deterministicVersioner) GetTokenizationVersion() (byte, error) {
	if d.tokError {
		return 0, errors.New("no available version")
	}
	return d.tokVersion, nil
}

func (d deterministicVersioner) GetDetokenizationVersions() ([]byte, error) {
	if d.detokError {
		return nil, errors.New("no available versions")
	}
	return d.detokVersions, nil
}

type fixedKeyRepo struct {
	err bool
	key []byte
}

func (f fixedKeyRepo) GetKey(_ byte) ([]byte, error) {
	if f.err {
		return nil, errors.New("version does not exist")
	}
	return f.key, nil
}

type missingBase14AlphaProvider struct{}

func (d missingBase14AlphaProvider) GetAlphabetForBase(base uint32) ([]byte, error) {
	b := map[uint32][]byte{
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

type wrongSizeBase14AlphaProvider struct{}

func (d wrongSizeBase14AlphaProvider) GetAlphabetForBase(base uint32) ([]byte, error) {
	b := map[uint32][]byte{
		uint32(14): {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm'},
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

type duplicatedSymbolsBase14AlphaProvider struct{}

func (d duplicatedSymbolsBase14AlphaProvider) GetAlphabetForBase(base uint32) ([]byte, error) {
	b := map[uint32][]byte{
		uint32(14): {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'm'},
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

func Test_bitsRequired(t *testing.T) {
	tests := map[string]struct {
		n    uint32
		want uint32
	}{
		"99_7":        {99, 7},
		"999_10":      {999, 10},
		"9999_14":     {9999, 14},
		"99999_17":    {99999, 17},
		"999999_20":   {999999, 20},
		"9999999_24":  {9999999, 24},
		"99999999_24": {99999999, 27},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := bitsRequired(tt.n); got != tt.want {
				t.Errorf("bitsRequired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_encodeTkMD(t *testing.T) {
	tests := map[string]struct {
		ciphertext string
		want       string
		wantErr    bool
	}{
		"000_aa":          {"000", "aa", false},
		"001_ab":          {"001", "ab", false},
		"021_av":          {"021", "av", false},
		"352_la":          {"352", "la", false},
		"353_av":          {"353", "lb", false},
		"00001_aaab":      {"00001", "aaab", false},
		"too_short_error": {"53", "", true},
		"too_long_error":  {"0123456789", "", true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := encodeTkMD(tt.ciphertext, DefaultAlphabetProvider{})
			if (err != nil) != tt.wantErr {
				t.Errorf("encodeTkMD() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("encodeTkMD() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_decodeTkMD(t *testing.T) {
	tests := map[string]struct {
		tkMD    string
		want    string
		wantErr bool
	}{
		"aa_000":          {"aa", "000", false},
		"ab_001":          {"ab", "001", false},
		"av_021":          {"av", "021", false},
		"la_352":          {"la", "352", false},
		"lb_353":          {"lb", "353", false},
		"aaab_00001":      {"aaab", "00001", false},
		"too_short_error": {"3", "", true},
		"too_long_error":  {"012345678", "", true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := decodeTkMD(tt.tkMD, DefaultAlphabetProvider{})
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeTkMD() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("decodeTkMD() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_engine_EncryptCC(t *testing.T) {

	type fields struct {
		versioner      KeyVersioner
		encryptionKeys KeyRepo
		hmacKeys       KeyRepo
	}
	type args struct {
		cc string
	}
	tests := map[string]struct {
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		"nominal_tokenization": {
			fields: fields{
				versioner: deterministicVersioner{
					tokError:      false,
					detokError:    false,
					tokVersion:    byte('a'),
					detokVersions: []byte{'a', 'b', 'c', 'd'},
				},
				encryptionKeys: fixedKeyRepo{false, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
				hmacKeys:       fixedKeyRepo{false, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
			},
			args:    args{"4444333322221111"},
			want:    "444433aapchc1111",
			wantErr: false,
		},
		"invalid_input_cc": {
			fields: fields{
				versioner: deterministicVersioner{
					tokError:      false,
					detokError:    false,
					tokVersion:    byte('a'),
					detokVersions: []byte{'a', 'b', 'c', 'd'},
				},
				encryptionKeys: fixedKeyRepo{false, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
				hmacKeys:       fixedKeyRepo{false, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
			},
			args:    args{"A444333322221111"},
			want:    "",
			wantErr: true,
		},
		"versioner_error": {
			fields: fields{
				versioner: deterministicVersioner{
					tokError:      true,
					detokError:    false,
					tokVersion:    byte('a'),
					detokVersions: []byte{'a', 'b', 'c', 'd'},
				},
				encryptionKeys: fixedKeyRepo{false, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
				hmacKeys:       fixedKeyRepo{false, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
			},
			args:    args{"4444333322221111"},
			want:    "",
			wantErr: true,
		},
		"enc_key_repo_error": {
			fields: fields{
				versioner: deterministicVersioner{
					tokError:      false,
					detokError:    false,
					tokVersion:    byte('a'),
					detokVersions: []byte{'a', 'b', 'c', 'd'},
				},
				encryptionKeys: fixedKeyRepo{true, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
				hmacKeys:       fixedKeyRepo{false, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
			},
			args:    args{"4444333322221111"},
			want:    "",
			wantErr: true,
		},
		"hmac_key_repo_error": {
			fields: fields{
				versioner: deterministicVersioner{
					tokError:      false,
					detokError:    false,
					tokVersion:    byte('a'),
					detokVersions: []byte{'a', 'b', 'c', 'd'},
				},
				encryptionKeys: fixedKeyRepo{false, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
				hmacKeys:       fixedKeyRepo{true, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
			},
			args:    args{"4444333322221111"},
			want:    "",
			wantErr: true,
		},
		"encryption_error_key_must_be_128_192_256": {
			fields: fields{
				versioner: deterministicVersioner{
					tokError:      false,
					detokError:    false,
					tokVersion:    byte('a'),
					detokVersions: []byte{'a', 'b', 'c', 'd'},
				},
				encryptionKeys: fixedKeyRepo{false, []byte{}},
				hmacKeys:       fixedKeyRepo{false, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
			},
			args:    args{"4444333322221111"},
			want:    "",
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			e := &engine{
				versioner:      tt.fields.versioner,
				encryptionKeys: tt.fields.encryptionKeys,
				hmacKeys:       tt.fields.hmacKeys,
				alphaProvider:  DefaultAlphabetProvider{},
			}
			got, err := e.EncryptCC(tt.args.cc)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptCC() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("EncryptCC() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_engine_DecryptTK(t *testing.T) {
	type fields struct {
		versioner      KeyVersioner
		encryptionKeys KeyRepo
		hmacKeys       KeyRepo
	}
	type args struct {
		tk string
	}
	tests := map[string]struct {
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		"nominal_detokenization": {
			fields: fields{
				versioner: deterministicVersioner{
					tokError:      false,
					detokError:    false,
					tokVersion:    byte('a'),
					detokVersions: []byte{'a', 'b', 'c', 'd'},
				},
				encryptionKeys: fixedKeyRepo{false, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
				hmacKeys:       fixedKeyRepo{false, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
			},
			args:    args{"444433aapchc1111"},
			want:    "4444333322221111",
			wantErr: false,
		},
		"token_with_f_version_and_no_f_version_availlable_for_detok": {
			fields: fields{
				versioner: deterministicVersioner{
					tokError:      false,
					detokError:    false,
					tokVersion:    byte('a'),
					detokVersions: []byte{'a', 'b', 'c', 'd'},
				},
				encryptionKeys: fixedKeyRepo{false, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
				hmacKeys:       fixedKeyRepo{false, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
			},
			args:    args{"444433fapchc1111"},
			want:    "",
			wantErr: true,
		},
		"invalid_input_TK": {
			fields: fields{
				versioner: deterministicVersioner{
					tokError:      false,
					detokError:    false,
					tokVersion:    byte('a'),
					detokVersions: []byte{'a', 'b', 'c', 'd'},
				},
				encryptionKeys: fixedKeyRepo{false, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
				hmacKeys:       fixedKeyRepo{false, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
			},
			args:    args{"444333322221111"},
			want:    "",
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			e := &engine{
				versioner:      tt.fields.versioner,
				encryptionKeys: tt.fields.encryptionKeys,
				hmacKeys:       tt.fields.hmacKeys,
				alphaProvider:  DefaultAlphabetProvider{},
			}
			got, err := e.DecryptTK(tt.args.tk)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptTK() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("DecryptTK() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewEngine(t *testing.T) {
	type args struct {
		versioner      KeyVersioner
		encryptionKeys KeyRepo
		hmacKeys       KeyRepo
		alphaProvider  AlphabetProvider
	}
	tests := map[string]struct {
		args    args
		wantErr bool
	}{
		"nominal_engine": {
			args: args{
				versioner: deterministicVersioner{
					tokError:      false,
					detokError:    false,
					tokVersion:    byte('a'),
					detokVersions: []byte{'a', 'b', 'c', 'd'},
				},
				encryptionKeys: fixedKeyRepo{false, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
				hmacKeys:       fixedKeyRepo{false, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
				alphaProvider:  DefaultAlphabetProvider{},
			},
			wantErr: false,
		},
		"error_due_to_missing_base_14_alphabet": {
			args: args{
				versioner: deterministicVersioner{
					tokError:      false,
					detokError:    false,
					tokVersion:    byte('a'),
					detokVersions: []byte{'a', 'b', 'c', 'd'},
				},
				encryptionKeys: fixedKeyRepo{false, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
				hmacKeys:       fixedKeyRepo{false, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
				alphaProvider:  missingBase14AlphaProvider{},
			},
			wantErr: true,
		},
		"error_due_to_wrong_sized_alphabet_in_base_14_alphabet": {
			args: args{
				versioner: deterministicVersioner{
					tokError:      false,
					detokError:    false,
					tokVersion:    byte('a'),
					detokVersions: []byte{'a', 'b', 'c', 'd'},
				},
				encryptionKeys: fixedKeyRepo{false, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
				hmacKeys:       fixedKeyRepo{false, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
				alphaProvider:  wrongSizeBase14AlphaProvider{},
			},
			wantErr: true,
		},
		"error_due_to_duplicated_symbols_in_base_14_alphabet": {
			args: args{
				versioner: deterministicVersioner{
					tokError:      false,
					detokError:    false,
					tokVersion:    byte('a'),
					detokVersions: []byte{'a', 'b', 'c', 'd'},
				},
				encryptionKeys: fixedKeyRepo{false, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
				hmacKeys:       fixedKeyRepo{false, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
				alphaProvider:  duplicatedSymbolsBase14AlphaProvider{},
			},
			wantErr: true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := NewEngine(tt.args.versioner, tt.args.encryptionKeys, tt.args.hmacKeys, tt.args.alphaProvider)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewEngine() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

