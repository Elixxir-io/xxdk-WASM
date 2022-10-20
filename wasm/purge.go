////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

package wasm

// NumClientsRunning is an atomic that tracks the current number of Cmix
// followers that have been started. Every time one is started, this counter
// must be incremented and every time one is stopped, it must be decremented.
//
// This variable is an atomic. Only access it with atomic functions
var NumClientsRunning uint64
