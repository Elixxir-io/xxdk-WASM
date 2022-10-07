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

	// Attempt to decrypt
	decryptedInternalPassword, err :=
		decryptPassword(encryptedInternalPassword, externalPassword)
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
	password := "test_password"
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
	_, err := decryptPassword(ciphertext, "dummyPassword")
	expectedErr := fmt.Sprintf(readNonceLenErr, 24)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Unexpected error on short decryption."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}

	// Empty string shouldn't panic should cause an error.
	ciphertext = []byte{}
	_, err = decryptPassword(ciphertext, "dummyPassword")
	expectedErr = fmt.Sprintf(readNonceLenErr, 0)
	if err == nil || !strings.Contains(err.Error(), expectedErr) {
		t.Errorf("Unexpected error on short decryption."+
			"\nexpected: %s\nreceived: %+v", expectedErr, err)
	}
}
