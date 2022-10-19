////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

//go:build js && wasm

package main

import (
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/client/bindings"
	"gitlab.com/elixxir/xxdk-wasm/utils"
	"os"
)

// SEMVER is the current semantic version of xxDK WASM.
const SEMVER = "0.0.0"

// Storage keys.
const (
	semverKey    = "xxdkWasmSemanticVersion"
	clientVerKey = "xxdkClientSemanticVersion"
)

// CheckAndStoreVersions checks that the stored xxDK WASM version matches the
// current version and if not, upgrades it. It also stored the current xxDK
// client to storage.
//
// On first load, only the xxDK WASM and xxDK client versions are stored.
func CheckAndStoreVersions() error {
	return checkAndStoreVersions(
		SEMVER, bindings.GetVersion(), utils.GetLocalStorage())
}
func checkAndStoreVersions(
	currentWasmVer, currentClientVer string, ls *utils.LocalStorage) error {
	// Get the stored client version, if it exists and save the new one
	storedClientVer, err := initOrLoadStoredSemver(
		clientVerKey, currentClientVer, ls)
	if err != nil {
		return err
	}
	if storedClientVer != currentClientVer {
		jww.INFO.Printf("Upgrading xxDK version: v%s → v%s",
			storedClientVer, currentClientVer)
		ls.SetItem(clientVerKey, []byte(currentClientVer))
	}

	// Get the stored version, if it exists
	storedWasmVer, err := initOrLoadStoredSemver(semverKey, currentWasmVer, ls)
	if err != nil {
		return err
	}

	// Check if the stored version is current
	if storedWasmVer == currentWasmVer {
		jww.INFO.Printf("xxDK WASM version is current: v%s", storedWasmVer)
		return nil
	}

	jww.INFO.Printf("xxDK WASM version is out of date. "+
		"Upgrading versions: v%s → v%s", storedWasmVer, currentWasmVer)

	// Upgrade old version
	switch storedWasmVer {
	case "-1.0.0":
		// upgrade path
	default:
		jww.INFO.Printf("No upgrade path found for %s", storedWasmVer)
	}

	ls.SetItem(semverKey, []byte(currentWasmVer))

	return nil
}

// initOrLoadStoredSemver returns the semantic version stored at the key in
// local storage. If no version is stored, then the current version is stored
// and returned.
func initOrLoadStoredSemver(
	key, currentVersion string, ls *utils.LocalStorage) (string, error) {
	storedVersion, err := ls.GetItem(key)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Save the current version if this is the first run
			jww.INFO.Printf("Initialising %s to v%s", key, currentVersion)
			ls.SetItem(key, []byte(currentVersion))
			return currentVersion, nil
		} else {
			// If the item exists, but cannot be loaded, return an error
			return "", errors.Errorf(
				"could not load %s from storage: %+v", key, err)
		}
	}

	// Return the stored version
	return string(storedVersion), nil
}
