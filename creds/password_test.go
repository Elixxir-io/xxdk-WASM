////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

//go:build js && wasm

package creds

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"gitlab.com/elixxir/xxdk-wasm/utils"
	"gitlab.com/xx_network/crypto/csprng"
	"strings"
	"testing"
)

// Tests that running GetOrInit twice returns the same internal password both
// times.
func TestGetOrInit(t *testing.T) {
	externalPassword := "myPassword"
	internalPassword, err := GetOrInit(externalPassword)
	if err != nil {
		t.Errorf("%+v", err)
	}

	loadedInternalPassword, err := GetOrInit(externalPassword)
	if err != nil {
		t.Errorf("%+v", err)
	}

	if !bytes.Equal(internalPassword, loadedInternalPassword) {
		t.Errorf("Internal password from storage does not match original."+
			"\nexpected: %+v\nreceived: %+v",
			internalPassword, loadedInternalPassword)
	}
}

func TestChangeExternalPassword(t *testing.T) {
	oldExternalPassword := "myPassword"
	newExternalPassword := "hunter2"
	oldInternalPassword, err := GetOrInit(oldExternalPassword)
	if err != nil {
		t.Errorf("%+v", err)
	}

	err = ChangeExternalPassword(oldExternalPassword, newExternalPassword)
	if err != nil {
		t.Errorf("%+v", err)
	}

	newInternalPassword, err := GetOrInit(newExternalPassword)
	if err != nil {
		t.Errorf("%+v", err)
	}

	if !bytes.Equal(oldInternalPassword, newInternalPassword) {
		t.Errorf("Internal password was not changed in storage. Old and new "+
			"should be different.\nold: %+v\nnew: %+v",
			oldInternalPassword, newInternalPassword)
	}

	_, err = GetOrInit(oldExternalPassword)
	expectedErr := strings.Split(decryptWithPasswordErr, "%")[0]
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Unexpected error when trying to get internal password with "+
			"old external password.\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Tests that the internal password returned by initInternalPassword matches
// the encrypted one saved to local storage.
func Test_initInternalPassword(t *testing.T) {
	externalPassword := "myPassword"
	ls := utils.GetLocalStorage()
	rng := csprng.NewSystemRNG()

	internalPassword, err := initInternalPassword(externalPassword, ls, rng)
	if err != nil {
		t.Errorf("%+v", err)
	}

	// Attempt to retrieve encrypted internal password from storage
	encryptedInternalPassword, err := ls.GetItem(passwordKey)
	if err != nil {
		t.Errorf(
			"Failed to load encrypted internal password from storage: %+v", err)
	}

	// Attempt to retrieve salt from storage
	salt, err := ls.GetItem(saltKey)
	if err != nil {
		t.Errorf("Failed to load salt from storage: %+v", err)
	}

	// Attempt to decrypt
	key := deriveKey(externalPassword, salt, defaultParams())
	decryptedInternalPassword, err :=
		decryptPassword(encryptedInternalPassword, key)
	if err != nil {
		t.Errorf("Failed to load decrpyt internal password: %+v", err)
	}

	if !bytes.Equal(internalPassword, decryptedInternalPassword) {
		t.Errorf("Decrypted internal password from storage does not match "+
			"original.\nexpected: %+v\nreceived: %+v",
			internalPassword, decryptedInternalPassword)
	}
}

// Tests that getInternalPassword returns the internal password that is saved
// to local storage by initInternalPassword.
func Test_getInternalPassword(t *testing.T) {
	externalPassword := "myPassword"
	ls := utils.GetLocalStorage()
	rng := csprng.NewSystemRNG()

	internalPassword, err := initInternalPassword(externalPassword, ls, rng)
	if err != nil {
		t.Errorf("%+v", err)
	}

	loadedInternalPassword, err := getInternalPassword(externalPassword, ls)
	if err != nil {
		t.Errorf("%+v", err)
	}

	if !bytes.Equal(internalPassword, loadedInternalPassword) {
		t.Errorf("Internal password from storage does not match original."+
			"\nexpected: %+v\nreceived: %+v",
			internalPassword, loadedInternalPassword)
	}
}

// Smoke test of encryptPassword and decryptPassword.
func Test_encryptPassword_decryptPassword(t *testing.T) {
	plaintext := []byte("Hello, World!")
	password := []byte("test_password")
	ciphertext := encryptPassword(plaintext, password, rand.Reader)
	decrypted, err := decryptPassword(ciphertext, password)
	if err != nil {
		t.Errorf("%+v", err)
	}

	for i := range plaintext {
		if plaintext[i] != decrypted[i] {
			t.Errorf("%b != %b", plaintext[i], decrypted[i])
		}
	}
}

// Tests that decryptPassword does not panic when given too little data.
func Test_decryptPassword_ShortData(t *testing.T) {
	// Anything under 24 should cause an error.
	ciphertext := []byte{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	_, err := decryptPassword(ciphertext, []byte("dummyPassword"))
	expectedErr := fmt.Sprintf(readNonceLenErr, 24)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Unexpected error on short decryption."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}

	// Empty string shouldn't panic should cause an error.
	ciphertext = []byte{}
	_, err = decryptPassword(ciphertext, []byte("dummyPassword"))
	expectedErr = fmt.Sprintf(readNonceLenErr, 0)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Unexpected error on short decryption."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}

// Tests that deriveKey returns a key of the correct length and that it is the
// same for the same set of password and salt. Also checks that keys with the
// same salt or passwords do not collide.
func TestDeriveKey(t *testing.T) {
	p := testParams()
	salts := make([][]byte, 6)
	passwords := make([]string, len(salts))
	keys := make(map[string]bool, len(salts)*len(passwords))

	for i := range salts {
		prng := csprng.NewSystemRNG()
		salt, _ := makeSalt(prng)
		salts[i] = salt

		password := make([]byte, 16)
		_, _ = prng.Read(password)
		passwords[i] = base64.StdEncoding.EncodeToString(password)[:16]
	}

	for _, salt := range salts {
		for _, password := range passwords {
			key := deriveKey(password, salt, p)

			// Check that the length of the key is correct
			if len(key) != keyLen {
				t.Errorf("Incorrect key length.\nexpected: %d\nreceived: %d",
					keyLen, len(key))
			}

			// Check that the same key is generated when the same password and salt
			// are used
			key2 := deriveKey(password, salt, p)

			if !bytes.Equal(key, key2) {
				t.Errorf("Keys with same password and salt do not match."+
					"\nexpected: %v\nreceived: %v", key, key2)
			}

			if keys[string(key)] {
				t.Errorf("Key already exists.")
			}
			keys[string(key)] = true
		}
	}
}

// Tests that multiple calls to makeSalt results in unique salts of the
// specified length.
func TestMakeSalt(t *testing.T) {
	salts := make(map[string]bool, 50)
	for i := 0; i < 50; i++ {
		salt, err := makeSalt(csprng.NewSystemRNG())
		if err != nil {
			t.Errorf("MakeSalt returned an error: %+v", err)
		}

		if len(salt) != saltLen {
			t.Errorf("Incorrect salt length.\nexpected: %d\nreceived: %d",
				saltLen, len(salt))
		}

		if salts[string(salt)] {
			t.Errorf("Salt already exists (%d).", i)
		}
		salts[string(salt)] = true
	}
}

// testParams returns params used in testing that are quick.
func testParams() argonParams {
	return argonParams{
		Time:    1,
		Memory:  1,
		Threads: 1,
	}
}
