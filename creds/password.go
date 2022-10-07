////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

//go:build js && wasm

package creds

import (
	"crypto/cipher"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/xxdk-wasm/utils"
	"gitlab.com/xx_network/crypto/csprng"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
	"os"
	"syscall/js"
)

const (
	// Length of the internal password (256-bit)
	internalPasswordLen = 32

	// Key used to store the encrypted internal password in local storage
	passwordKey = "xxEncryptedInternalPassword"
)

// Error messages.
const (
	// getInternalPassword
	getPasswordStorageErr = "could not retrieve encrypted internal password from storage: %+v"
	decryptPasswordErr    = "could not decrypt internal password: %+v"

	// initInternalPassword
	readInternalPasswordErr     = "could not generate internal password: %+v"
	internalPasswordNumBytesErr = "expected %d bytes for internal password, found %d bytes"
	// decryptPassword
	readNonceLenErr        = "read %d bytes, too short to decrypt"
	decryptWithPasswordErr = "cannot decrypt with password: %+v"
)

// GetOrInitJS takes a user-provided password and returns its associated 256-bit
// internal password.
//
// If the internal password has not previously been created, then it is
// generated, saved to local storage, and returned. If the internal password has
// been previously generated, it is retrieved from local storage and returned.
//
// Any password saved to local storage is encrypted using the user-provided
// password.
//
// Parameters:
//  - args[0] - The user supplied password (string).
//
// Returns:
//  - Internal password (Uint8Array).
//  - Throws TypeError on failure.
func GetOrInitJS(_ js.Value, args []js.Value) interface{} {
	internalPassword, err := GetOrInit(args[0].String())
	if err != nil {
		utils.Throw(utils.TypeError, err)
		return nil
	}

	return utils.CopyBytesToJS(internalPassword)
}

// ChangeExternalPasswordJS allows a user to change their external password.
//
// Parameters:
//  - args[0] - The user's old password (string).
//  - args[1] - The user's new password (string).
//
// Returns:
//  - Throws TypeError on failure.
func ChangeExternalPasswordJS(_ js.Value, args []js.Value) interface{} {
	err := ChangeExternalPassword(args[0].String(), args[1].String())
	if err != nil {
		utils.Throw(utils.TypeError, err)
		return nil
	}

	return nil
}

// GetOrInit takes a user-provided password and returns its associated 256-bit
// internal password.
//
// If the internal password has not previously been created, then it is
// generated, saved to local storage, and returned. If the internal password has
// been previously generated, it is retrieved from local storage and returned.
//
// Any password saved to local storage is encrypted using the user-provided
// password.
func GetOrInit(externalPassword string) ([]byte, error) {
	localStorage := utils.GetLocalStorage()
	internalPassword, err := getInternalPassword(externalPassword, localStorage)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			rng := csprng.NewSystemRNG()
			return initInternalPassword(externalPassword, localStorage, rng)
		}

		return nil, err
	}

	return internalPassword, nil
}

// ChangeExternalPassword allows a user to change their external password.
func ChangeExternalPassword(oldExternalPassword, newExternalPassword string) error {
	localStorage := utils.GetLocalStorage()
	internalPassword, err := getInternalPassword(oldExternalPassword, localStorage)
	if err != nil {
		return err
	}

	encryptedInternalPassword := encryptPassword(
		internalPassword, newExternalPassword, csprng.NewSystemRNG())
	localStorage.SetItem(passwordKey, encryptedInternalPassword)

	return nil
}

// initInternalPassword generates a new internal password, stores an encrypted
// version in local storage, and returns it.
func initInternalPassword(externalPassword string,
	localStorage *utils.LocalStorage, csprng io.Reader) ([]byte, error) {
	internalPassword := make([]byte, internalPasswordLen)

	n, err := csprng.Read(internalPassword)
	if err != nil {
		return nil, errors.Errorf(readInternalPasswordErr, err)
	} else if n != internalPasswordLen {
		return nil, errors.Errorf(
			internalPasswordNumBytesErr, internalPasswordLen, n)
	}

	encryptedInternalPassword := encryptPassword(
		internalPassword, externalPassword, csprng)
	localStorage.SetItem(passwordKey, encryptedInternalPassword)

	return internalPassword, nil
}

// getInternalPassword retrieves the internal password from local storage,
// decrypts it, and returns it.
func getInternalPassword(
	externalPassword string, localStorage *utils.LocalStorage) ([]byte, error) {
	encryptedInternalPassword, err := localStorage.GetItem(passwordKey)
	if err != nil {
		return nil, errors.WithMessage(err, getPasswordStorageErr)
	}

	decryptedInternalPassword, err :=
		decryptPassword(encryptedInternalPassword, externalPassword)
	if err != nil {
		return nil, errors.Errorf(decryptPasswordErr, err)
	}

	return decryptedInternalPassword, nil
}

// encryptPassword encrypts the data for a shared URL using XChaCha20-Poly1305.
func encryptPassword(data []byte, password string, csprng io.Reader) []byte {
	chaCipher := initChaCha20Poly1305(password)
	nonce := make([]byte, chaCipher.NonceSize())
	if _, err := io.ReadFull(csprng, nonce); err != nil {
		jww.FATAL.Panicf("Could not generate nonce %+v", err)
	}
	ciphertext := chaCipher.Seal(nonce, nonce, data, nil)
	return ciphertext
}

// decryptPassword decrypts the encrypted data from a shared URL using
// XChaCha20-Poly1305.
func decryptPassword(data []byte, password string) ([]byte, error) {
	chaCipher := initChaCha20Poly1305(password)
	nonceLen := chaCipher.NonceSize()
	if (len(data) - nonceLen) <= 0 {
		return nil, errors.Errorf(readNonceLenErr, len(data))
	}
	nonce, ciphertext := data[:nonceLen], data[nonceLen:]
	plaintext, err := chaCipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.Errorf(decryptWithPasswordErr, err)
	}
	return plaintext, nil
}

// initChaCha20Poly1305 returns a XChaCha20-Poly1305 cipher.AEAD that uses the
// given password hashed into a 256-bit key.
func initChaCha20Poly1305(password string) cipher.AEAD {
	pwHash := blake2b.Sum256([]byte(password))
	chaCipher, err := chacha20poly1305.NewX(pwHash[:])
	if err != nil {
		jww.FATAL.Panicf("Could not init XChaCha20Poly1305 mode: %+v", err)
	}

	return chaCipher
}
