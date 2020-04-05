package argon2

import (
	"fmt"
	"log"
	"reflect"
	"testing"
)

// Tests

func TestCompareHashAndPassword(t *testing.T) {
	type args struct {
		hash     []byte
		password []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "valid hash password couple",
			args: args{
				hash:     []byte("argon2id$19$65536$3$2$6pAg+fVI2vB9uenAuOTK0A$VPg50e+vxRnvQ8dIFSg1HFNYHYcxEW+Dx47O6vipImU"),
				password: []byte("qwerty123"),
			},
			wantErr: false,
		},
		{
			name: "invalid hash password couple",
			args: args{
				hash:     []byte("argon2id$19$65536$3$2$6pAg+fVI6vB9uynAuOTK0B$VPg50e+vxRnvQ9dIFSg1HFNYHYcxEW+Dx47O6vipImU"),
				password: []byte("qwerty123"),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := CompareHashAndPassword(tt.args.hash, tt.args.password); (err != nil) != tt.wantErr {
				t.Errorf("CompareHashAndPassword() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGenerateFromPassword(t *testing.T) {
	type args struct {
		password []byte
		p        *Params
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "valid params",
			args: args{
				password: []byte("qwerty123"),
				p:        &Params{Memory: 32 * 1024, Iterations: 2, Parallelism: 2, SaltLength: 16, KeyLength: 32},
			},
			wantErr: false,
		},
		{
			name: "minimum valid params values",
			args: args{
				password: []byte("qwerty123"),
				p:        &Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 8, KeyLength: 16},
			},
			wantErr: false,
		},
		{
			name: "another valid params values",
			args: args{
				password: []byte("qwerty123"),
				p:        &Params{Memory: 64 * 1024, Iterations: 3, Parallelism: 4, SaltLength: 32, KeyLength: 64},
			},
			wantErr: false,
		},
		{
			name: "invalid Memory",
			args: args{
				password: []byte("qwerty123"),
				p:        &Params{Memory: 4 * 1024, Iterations: 3, Parallelism: 2, SaltLength: 16, KeyLength: 32},
			},
			wantErr: true,
		},
		{
			name: "invalid Iterations",
			args: args{
				password: []byte("qwerty123"),
				p:        &Params{Memory: 64 * 1024, Iterations: 0, Parallelism: 2, SaltLength: 16, KeyLength: 32},
			},
			wantErr: true,
		},
		{
			name: "invalid Parallelism",
			args: args{
				password: []byte("qwerty123"),
				p:        &Params{Memory: 64 * 1024, Iterations: 3, Parallelism: 0, SaltLength: 16, KeyLength: 32},
			},
			wantErr: true,
		},
		{
			name: "invalid SaltLength",
			args: args{
				password: []byte("qwerty123"),
				p:        &Params{Memory: 64 * 1024, Iterations: 3, Parallelism: 2, SaltLength: 4, KeyLength: 32},
			},
			wantErr: true,
		},
		{
			name: "invalid KeyLength",
			args: args{
				password: []byte("qwerty123"),
				p:        &Params{Memory: 64 * 1024, Iterations: 3, Parallelism: 2, SaltLength: 16, KeyLength: 8},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GenerateFromPassword(tt.args.password, tt.args.p)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateFromPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	type args struct {
		n uint32
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		wantLen int
	}{
		{
			name:    "length 1",
			args:    args{1},
			wantErr: false,
			wantLen: 1,
		},
		{
			name:    "length 8",
			args:    args{8},
			wantErr: false,
			wantLen: 8,
		},
		{
			name:    "length 16",
			args:    args{16},
			wantErr: false,
			wantLen: 16,
		},
		{
			name:    "length 32",
			args:    args{32},
			wantErr: false,
			wantLen: 32,
		},
		{
			name:    "length 128",
			args:    args{128},
			wantErr: false,
			wantLen: 128,
		},
		{
			name:    "length 512",
			args:    args{512},
			wantErr: false,
			wantLen: 512,
		},
		{
			name:    "length 2048",
			args:    args{2048},
			wantErr: false,
			wantLen: 2048,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateRandomBytes(tt.args.n)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateRandomBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			fmt.Println(len(got))
			if !reflect.DeepEqual(len(got), tt.wantLen) {
				t.Errorf("GenerateRandomBytes() got len = %v, want len %v", got, tt.wantLen)
			}
		})
	}
}

func TestParams_Check(t *testing.T) {
	type fields struct {
		Memory      uint32
		Iterations  uint32
		Parallelism uint8
		SaltLength  uint32
		KeyLength   uint32
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name:    "minimum values",
			fields:  fields{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 8, KeyLength: 16},
			wantErr: false,
		},
		{
			name:    "valid values",
			fields:  fields{Memory: 32 * 1024, Iterations: 2, Parallelism: 2, SaltLength: 16, KeyLength: 32},
			wantErr: false,
		},
		{
			name:    "valid values 2",
			fields:  fields{Memory: 64 * 1024, Iterations: 3, Parallelism: 4, SaltLength: 32, KeyLength: 64},
			wantErr: false,
		},
		{
			name:    "valid values 3",
			fields:  fields{Memory: 256 * 1024, Iterations: 4, Parallelism: 8, SaltLength: 64, KeyLength: 128},
			wantErr: false,
		},
		{
			name:    "invalid Memory",
			fields:  fields{Memory: 4 * 1024, Iterations: 3, Parallelism: 2, SaltLength: 16, KeyLength: 32},
			wantErr: true,
		},
		{
			name:    "invalid Iterations",
			fields:  fields{Memory: 64 * 1024, Iterations: 0, Parallelism: 2, SaltLength: 16, KeyLength: 32},
			wantErr: true,
		},
		{
			name:    "invalid Parallelism",
			fields:  fields{Memory: 64 * 1024, Iterations: 3, Parallelism: 0, SaltLength: 16, KeyLength: 32},
			wantErr: true,
		},
		{
			name:    "invalid SaltLength",
			fields:  fields{Memory: 64 * 1024, Iterations: 3, Parallelism: 2, SaltLength: 4, KeyLength: 32},
			wantErr: true,
		},
		{
			name:    "invalid KeyLength",
			fields:  fields{Memory: 64 * 1024, Iterations: 3, Parallelism: 2, SaltLength: 16, KeyLength: 8},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Params{
				Memory:      tt.fields.Memory,
				Iterations:  tt.fields.Iterations,
				Parallelism: tt.fields.Parallelism,
				SaltLength:  tt.fields.SaltLength,
				KeyLength:   tt.fields.KeyLength,
			}
			if err := p.Check(); (err != nil) != tt.wantErr {
				t.Errorf("Check() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_decodeHash(t *testing.T) {
	type args struct {
		encodedHash []byte
	}
	tests := []struct {
		name     string
		args     args
		wantP    *Params
		wantSalt []byte
		wantHash []byte
		wantErr  bool
	}{
		{
			name: "valid hash",
			args: args{[]byte("argon2id$19$65536$3$2$y9Mjl5CpHgKbRjloFZ5Agg$OuEhb6CmIeCMC3Jx3RgJFoeUSwo7S9OTrq20pFW/Fck")},
			wantP: &Params{
				Memory:      65536,
				Iterations:  3,
				Parallelism: 2,
				SaltLength:  16,
				KeyLength:   32,
			},
			wantSalt: []byte{203, 211, 35, 151, 144, 169, 30, 2, 155, 70, 57, 104, 21, 158, 64, 130},
			wantHash: []byte{58, 225, 33, 111, 160, 166, 33, 224, 140, 11, 114, 113, 221, 24, 9, 22, 135, 148, 75, 10, 59, 75, 211, 147, 174, 173, 180, 164, 85, 191, 21, 201},
		},
		{
			name:    "invalid hash length",
			args:    args{[]byte("argon2id$19$65536$3$2$y9Mjl5CpHgKbRjloFZ5Agg$OuEhb6CmIeCMC3Jx3RgJFoeUSwo7S9OTdeawf43v43rxwxrq20pFW/Fck")},
			wantErr: true,
		},
		{
			name:    "invalid hash metadata",
			args:    args{[]byte("argon2id$19$655$36$3$2$y9M$jl5CpHgKbRjloFZ5Agg$OuEhb6CmIeCMC3Jx3RgJFoeUSwo7S9OTrq20pFW/Fck")},
			wantErr: true,
		},
		{
			name:    "invalid params",
			args:    args{[]byte("argon2id$19$dsa$dw4w$de3$y9Mjl5CpHgKbRjloFZ5Agg$OuEhb6CmIeCMC3Jx3RgJFoeUSwo7S9OTrq20pFW/Fck")},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotP, gotSalt, gotHash, err := decodeHash(tt.args.encodedHash)
			if (err != nil) != tt.wantErr {
				t.Errorf("decodeHash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			fmt.Println(gotP)
			fmt.Println(gotSalt)
			fmt.Println(gotHash)

			if !reflect.DeepEqual(gotP, tt.wantP) {
				t.Errorf("decodeHash() gotP = %v, want %v", gotP, tt.wantP)
			}
			if !reflect.DeepEqual(gotSalt, tt.wantSalt) {
				t.Errorf("decodeHash() gotSalt = %v, want %v", gotSalt, tt.wantSalt)
			}
			if !reflect.DeepEqual(gotHash, tt.wantHash) {
				t.Errorf("decodeHash() gotHash = %v, want %v", gotHash, tt.wantHash)
			}
		})
	}
}

// Examples

func ExampleGenerateFromPassword() {
	// e.g. r.PostFormValue("password")
	passwordFromForm := "qwerty123"

	// Generates a derived key with default params
	hash, err := GenerateFromPassword([]byte(passwordFromForm), DefaultParams)
	if err != nil {
		log.Fatal(err)
	}

	// Print the derived key - "argon2id$19$65536$3$2$R8kBdA675bqNJbhWntdlAA$X28Igb1N0MBO3IWOIPoS+JxLmhAx0KBUYe65BSEsMs8"
	fmt.Printf("%s\n", hash)
}

func ExampleCompareHashAndPassword() {
	// e.g. r.PostFormValue("password")
	passwordFromForm := "qwerty123"

	// e.g. hash from database
	hash := "qwerty123"

	// Check password with a hash. Return an error if they don't match
	err := CompareHashAndPassword([]byte(hash), []byte(passwordFromForm))
	if err != nil {
		log.Fatal(err)
	}
	// Do something next
}
