////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

importScripts('wasm_exec.js');

const go = new Go();
const binPath = 'xxdk-indexedDkWorker.wasm'
WebAssembly.instantiateStreaming(fetch(binPath), go.importObject).then((result) => {
    go.run(result.instance);
}).catch((err) => {
    console.error(err);
});