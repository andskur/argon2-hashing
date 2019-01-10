package argon2

import (
	"fmt"
	"log"
	"testing"
)

var (
	testLengths = []uint32{1, 8, 16, 32, 128, 512, 2048}
	password    = "qwerty123"
)

var testParams = []struct {
	pass   bool
	params *Params
}{
	{true, &Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 8, KeyLength: 16}}, // minimum values
	{true, &Params{Memory: 32 * 1024, Iterations: 2, Parallelism: 2, SaltLength: 16, KeyLength: 32}},
	{true, &Params{Memory: 64 * 1024, Iterations: 3, Parallelism: 4, SaltLength: 32, KeyLength: 64}},
	{true, &Params{Memory: 256 * 1024, Iterations: 4, Parallelism: 8, SaltLength: 64, KeyLength: 128}},
	{false, &Params{Memory: 4 * 1024, Iterations: 3, Parallelism: 2, SaltLength: 16, KeyLength: 32}},  // invalid Memory
	{false, &Params{Memory: 64 * 1024, Iterations: 0, Parallelism: 2, SaltLength: 16, KeyLength: 32}}, // invalid Iterations
	{false, &Params{Memory: 64 * 1024, Iterations: 3, Parallelism: 0, SaltLength: 16, KeyLength: 32}}, // invalid Parallelism
	{false, &Params{Memory: 64 * 1024, Iterations: 3, Parallelism: 2, SaltLength: 4, KeyLength: 32}},  // invalid SaltLength
	{false, &Params{Memory: 64 * 1024, Iterations: 3, Parallelism: 2, SaltLength: 16, KeyLength: 8}},  // invalid KeyLength
}

func TestGenerateRandomBytes(t *testing.T) {
	for _, v := range testLengths {
		_, err := GenerateRandomBytes(v)
		if err != nil {
			t.Fatal("failed to generate random bytes")
		}
	}
}

func TestGenerateFromPassword(t *testing.T) {
	for _, v := range testParams {
		_, err := GenerateFromPassword([]byte(password), v.params)
		if err != nil && v.pass == true {
			t.Fatalf("no error was returned when expected for params: %+v", v.params)
		}
	}
}

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

func TestCompareHashAndPassword(t *testing.T) {
	hash, err := GenerateFromPassword([]byte(password), DefaultParams)
	if err != nil {
		t.Fatal(err)
	}

	if err := CompareHashAndPassword(hash, []byte(password)); err != nil {
		t.Fatal(err)
	}

	if err := CompareHashAndPassword(hash, []byte("invalid-password")); err == nil {
		t.Fatalf("mismatched passwords did not produce an error")
	}

	invalidHash := []byte("argon2id$19$65536$3$4$J3XY52LfC3pgj4gsqy646g$FQb/pMqSDAwZ51NfShsVsPKvLapOltJBlLlq3Qg3wX8")
	if err := CompareHashAndPassword(invalidHash, []byte(password)); err == nil {
		t.Fatalf("did not identify an invalid hash")
	}
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
