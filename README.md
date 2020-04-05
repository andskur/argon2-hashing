# argon2-hashing
[![GoDoc](https://godoc.org/github.com/elithrar/simple-scrypt?status.svg)](https://godoc.org/github.com/andskur/argon2-hashing) [![Build Status](https://travis-ci.org/andskur/argon2-hashing.svg?branch=master)](https://travis-ci.org/andskur/argon2-hashing)

**argon2-hashing** provides a light wrapper around Go's [argon2](https://godoc.org/golang.org/x/crypto/argon2) package.
Argon2 was the winner of the [Password Hashing](https://password-hashing.net) Competition that makes it easier to securely derive strong keys from weak
inputs (i.e. user passwords).

With this library you can:
* Generate a argon2 derived key with a crytographically secure salt and default parameters.
* Tune argon2 with you own parameters based of you hardware configuration.
* Compare a derived key with the possible cleartext equivalent (user password).

Currently supported only Argon2id function.

The API closely mirrors with Go's [Bcrypt library](https://godoc.org/golang.org/x/crypto/bcrypt)
and Alex Edwards [simple-scrypt package](https://github.com/elithrar/simple-scrypt).

## Installation

With a [Go modules](https://golang.org/doc/code.html):

```sh
go get -u github.com/andskur/argon2-hashing
```

## Example

argon2-hashing doesn't try to re-invent the wheel or do anything "special". It
wraps the `argon2.IDKey` function as thinly as possible, generates a
crytographically secure salt for you using Go's `crypto/rand` package, and
returns the derived key with the parameters prepended:

```go
package main

import(
    "fmt"
    "log"

    "github.com/andskur/argon2-hashing"
)

func main() {
    // e.g. r.PostFormValue("password")
    passwordFromForm := "qwerty123"

    // Generates a derived key with default params
    hash, err := argon2.GenerateFromPassword([]byte(passwordFromForm), argon2.DefaultParams)
    if err != nil {
        log.Fatal(err)
    }

    // Print the derived key.
    fmt.Printf("%s\n", hash)

    // Uses the parameters from the existing derived key. Return an error if they don't match.
    err = argon2.CompareHashAndPassword(hash, []byte(passwordFromForm))
    if err != nil {
        log.Fatal(err)
    }
}
```

## Argon2 introduction
The [Argon2 algorithm](https://tools.ietf.org/html/draft-irtf-cfrg-argon2-04) accepts a number of configurable parameters:

* Memory — The amount of memory used by the algorithm (in [kibibytes](https://en.wikipedia.org/wiki/Kibibyte)).
* Iterations — The number of iterations (or passes) over the memory.
* Parallelism — The number of threads (or lanes) used by the algorithm.
* Salt length — Length of the random salt. [16 bytes is recommended](https://tools.ietf.org/html/draft-irtf-cfrg-argon2-04#section-3.1) for password hashing.
* Key length — Length of the generated key (or password hash). 16 bytes or more is recommended.
* The memory and iterations parameters control the computational cost of hashing the password. The higher these figures are, the greater the cost of generating the hash. It also follows that the greater the cost will be for any attacker trying to guess the password.

But there's a balance that you need to strike. As you increase the cost, the time taken to generate the hash also increases. If you're generating the hash in response to a user action (like signing up or logging in to a website) then you probably want to keep the runtime to less than 500ms to avoid a negative user experience.

If the Argon2 algorithm is running on a machine with multiple cores, then one way to decrease the runtime without reducing the cost is to increase the parallelism parameter. This controls the number of threads that the work is spread across. There's an important thing to note here though: changing the value of the parallelism parameter changes the output of the algorithm. So — for example — running Argon2 with a parallelism parameter of 2 will result in a different password hash to running it with a parallelism parameter of 4.

### Choosing Parameters
Picking the right parameters for Argon2 depends heavily on the machine that the algorithm is running on, and you'll probably need to do some experimentation in order to set them appropriately.

The [recommended process](https://tools.ietf.org/html/draft-irtf-cfrg-argon2-04#section-4) for choosing the parameters can be paraphrased as follows:

1. Set the parallelism and memory parameters to the largest amount you are willing to afford, bearing in mind that you probably don't want to max these out completely unless your machine is dedicated to password hashing.
2. Increase the number of iterations until you reach your maximum runtime limit (for example, 500ms).
3. If you're already exceeding the your maximum runtime limit with the number of iterations = 1, then you should reduce the memory parameter.

## Thanks to
* [Alex Edwards](https://github.com/alexedwards) - For an excellent [article](https://www.alexedwards.net/blog/how-to-hash-and-verify-passwords-with-argon2-in-go), after which I was inspired to develop this package.
* [Matt Silverlock](https://github.com/elithrar) - For an great and well documented [simple-scrypt](https://github.com/elithrar/simple-scrypt) package which I took for the structural basis.

## Authors

* **Andrey Skurlatov** - [andskur](https://github.com/andskur)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details