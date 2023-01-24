////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

//go:build js && wasm

package main

import (
	"fmt"
	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/xxdk-wasm/wasm"
	"gitlab.com/elixxir/xxdk-wasm/worker"
	"syscall/js"
)

// SEMVER is the current semantic version of the xxDK channels web worker.
const SEMVER = "0.1.0"

func init() {
	// Set up Javascript console listener set at level INFO
	ll := wasm.NewJsConsoleLogListener(jww.LevelInfo)
	jww.SetLogListeners(ll.Listen)
	jww.SetStdoutThreshold(jww.LevelFatal + 1)
	jww.INFO.Printf("xxDK channels web worker version: v%s", SEMVER)
}

func main() {
	fmt.Println("[WW] Starting xxDK WebAssembly Channels Database Worker.")
	jww.INFO.Print("[WW] Starting xxDK WebAssembly Channels Database Worker.")

	js.Global().Set("LogLevel", js.FuncOf(wasm.LogLevel))
	js.Global().Set("LogToFile", js.FuncOf(wasm.LogToFile))
	js.Global().Set("RegisterLogWriter", js.FuncOf(wasm.RegisterLogWriter))

	m := &manager{mh: worker.NewThreadManager("ChannelsIndexedDbWorker", true)}
	m.registerCallbacks()
	m.mh.SignalReady()
	<-make(chan bool)
	fmt.Println("[WW] Closing xxDK WebAssembly Channels Database Worker.")
}
