// Package argon2 provides a convenience wrapper around Go's argon2 package
// Argon2 was the winner of the Password Hashing Competition
// that makes it easier to securely derive strong keys from weak
// inputs (i.e. user passwords).
// The package provides password generation, constant-time comparison and
// parameter upgrading for argon2 derived keys.
package argon2

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Constants for validate incoming Params.
const (
	minMemoryValue = 32 * 1024 // the minimum allowed memory amount
	minIteration   = 1         // the minimum time passes over the memory
	minThreads     = 1         // the minimum using threads
	minKeyLength   = 16        // the minimum derived key length in bytes
	minSaltLength  = 8         // the minimum allowed salt length in bytes
)

// Params describes the input parameters to the argon2 key derivation function.
// The time parameter specifies the number of passes over the memory and the
// memory parameter specifies the size of the memory in KiB. For example
// memory=64*1024 sets the memory cost to ~64 MB. The number of threads can be
// adjusted to the number of available CPUs. The cost parameters should be
// increased as memory latency and CPU parallelism increases. Remember to get a
// good random salt.
type Params struct {
	Memory     uint32 // The amount of memory used by the algorithm (kibibytes)
	Iterations uint32 // The number of iterations (passes) over the memory
	Threads    uint8  // The number of threads (lanes) used by the algorithm
	SaltLength uint32 // Length of the random salt. 16 bytes is recommended for password hashing
	KeyLength  uint32 // Length of the generated key (password hash). 16 bytes or more is recommended
}

// DefaultParams provides sensible default inputs into
// the argon2 function for interactive use.
// The default key length is 256 bits.
var DefaultParams = &Params{
	Memory:     64 * 1024,
	Iterations: 3,
	Threads:    2,
	SaltLength: 16,
	KeyLength:  32,
}

// ErrInvalidHash is returned when function failed to parse
// provided argon2 hash and/or given parameters.
var ErrInvalidHash = errors.New("argon2: the encoded hash is not in the correct format")

// ErrIncompatibleVersion is returned when version of provided argon2 hash
// s incompatible with current argon2 algorithm
var ErrIncompatibleVersion = errors.New("argon2: incompatible version of argon2")

// ErrMismatchedHashAndPassword is returned when a password (hashed) and
// given hash do not match.
var ErrMismatchedHashAndPassword = errors.New("argon2: the hashed password does not match the hash of the given password")

// GenerateFromPassword returns the derived key of the password using the
// parameters provided. The parameters are prepended to the derived key and
// separated by the "$" character
func GenerateFromPassword(password []byte, p *Params) ([]byte, error) {
	// Generate a cryptographically secure random salt
	salt, err := GenerateRandomBytes(p.SaltLength)
	if err != nil {
		return nil, err
	}

	// Pass the byte array password, salt and parameters to the argon2.IDKey
	// function. This will generate a hash of the password using the Argon2id variation.
	key := argon2.IDKey(password, salt, p.Iterations, p.Memory, p.Threads, p.KeyLength)

	// Encode salt and hashed password to Base64
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(key)

	return []byte(fmt.Sprintf("argon2id$%d$%d$%d$%d$%s$%s", argon2.Version, p.Memory, p.Iterations, p.Threads, b64Salt, b64Hash)), nil
}

// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// CompareHashAndPassword compares a derived key with the possible cleartext
// equivalent. The parameters used in the provided derived key are used.
// The comparison performed by this function is constant-time. It returns nil
// on success, and an error if the derived keys do not match.
func CompareHashAndPassword(hash, password []byte) error {
	p, salt, hash, err := decodeHash(hash)
	if err != nil {
		log.Fatal(err)
	}

	otherHash := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Threads, p.KeyLength)

	// Check that the contents of the hashed passwords are identical. Note
	// that we are using the subtle.ConstantTimeCompare() function for this
	// to help prevent timing attacks.
	if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
		return nil
	}
	return ErrMismatchedHashAndPassword
}

func decodeHash(encodedHash []byte) (p *Params, salt, hash []byte, err error) {
	vals := strings.Split(string(encodedHash), "$")

	if len(vals) != 7 {
		return nil, nil, nil, ErrInvalidHash
	}

	// Check argon2 version
	version, err := strconv.Atoi(vals[1])
	if err != nil {
		return nil, nil, nil, ErrInvalidHash
	}
	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	// Parsing parameters
	p = &Params{}

	memory, err := strconv.Atoi(vals[2])
	if err != nil {
		return nil, nil, nil, ErrInvalidHash
	}
	p.Memory = uint32(memory)

	iterations, err := strconv.Atoi(vals[3])
	if err != nil {
		return nil, nil, nil, ErrInvalidHash
	}
	p.Iterations = uint32(iterations)

	parallelism, err := strconv.Atoi(vals[4])
	if err != nil {
		return nil, nil, nil, ErrInvalidHash
	}
	p.Threads = uint8(parallelism)

	salt, err = base64.RawStdEncoding.DecodeString(vals[5])
	if err != nil {
		return nil, nil, nil, ErrInvalidHash
	}
	p.SaltLength = uint32(len(salt))

	hash, err = base64.RawStdEncoding.DecodeString(vals[6])
	if err != nil {
		return nil, nil, nil, ErrInvalidHash
	}
	p.KeyLength = uint32(len(hash))

	return p, salt, hash, nil
}
