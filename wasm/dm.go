////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

//go:build js && wasm

package wasm

import (
	"crypto/ed25519"
	"syscall/js"

	indexDB "gitlab.com/elixxir/xxdk-wasm/indexedDb/worker/dm"

	"encoding/base64"

	"gitlab.com/elixxir/client/v4/bindings"
	"gitlab.com/elixxir/crypto/codename"
	"gitlab.com/elixxir/xxdk-wasm/utils"
)

////////////////////////////////////////////////////////////////////////////////
// Basic Channel API                                                          //
////////////////////////////////////////////////////////////////////////////////

// DMClient wraps the [bindings.DMClient] object so its methods
// can be wrapped to be Javascript compatible.
type DMClient struct {
	api *bindings.DMClient
}

// newDMClientJS creates a new Javascript compatible object
// (map[string]any) that matches the [DMClient] structure.
func newDMClientJS(api *bindings.DMClient) map[string]any {
	cm := DMClient{api}
	dmClientMap := map[string]any{
		// Basic Channel API
		"GetID": js.FuncOf(cm.GetID),

		// Identity and Nickname Controls
		"GetPublicKey":          js.FuncOf(cm.GetPublicKey),
		"GetToken":              js.FuncOf(cm.GetToken),
		"GetIdentity":           js.FuncOf(cm.GetIdentity),
		"ExportPrivateIdentity": js.FuncOf(cm.ExportPrivateIdentity),
		"SetNickname":           js.FuncOf(cm.SetNickname),
		"GetNickname":           js.FuncOf(cm.GetNickname),
		"GetDatabaseName":       js.FuncOf(cm.GetDatabaseName),

		// DM Sending Methods and Reports
		"SendText":     js.FuncOf(cm.SendText),
		"SendReply":    js.FuncOf(cm.SendReply),
		"SendReaction": js.FuncOf(cm.SendReaction),
		"Send":         js.FuncOf(cm.Send),
	}

	return dmClientMap
}

// GetPublicKey returns the ecdh Public Key for this [DMClient] in the
// [DMClient] tracker.
//
// Returns:
//   - Tracker ID (int).
func (ch *DMClient) GetID(js.Value, []js.Value) any {
	return ch.api.GetID()
}

func (ch *DMClient) GetPublicKey(js.Value, []js.Value) any {
	return ch.api.GetPublicKey()
}

func (ch *DMClient) GetToken(js.Value, []js.Value) any {
	return ch.api.GetToken()
}

// dmReceiverBuilder adheres to the [bindings.DMReceiverBuilder] interface.
type dmReceiverBuilder struct {
	build func(args ...any) js.Value
}

// Build initializes and returns the event model.  It wraps a Javascript object
// that has all the methods in [bindings.EventModel] to make it adhere to the Go
// interface [bindings.EventModel].
func (emb *dmReceiverBuilder) Build(path string) bindings.DMReceiver {
	emJs := emb.build(path)
	return &dmReceiver{
		receive:          utils.WrapCB(emJs, "ReceiveText"),
		receiveText:      utils.WrapCB(emJs, "ReceiveText"),
		receiveReply:     utils.WrapCB(emJs, "ReceiveReply"),
		receiveReaction:  utils.WrapCB(emJs, "ReceiveReaction"),
		updateSentStatus: utils.WrapCB(emJs, "UpdateSentStatus"),
	}
}

// NewDMClient creates a new [DMClient] from a new private
// identity ([channel.PrivateIdentity]).
//
// Parameters:
//   - args[0] - ID of [Cmix] object in tracker (int). This can be retrieved
//     using [Cmix.GetID].
//   - args[1] - Bytes of a private identity ([channel.PrivateIdentity]) that is
//     generated by [GenerateChannelIdentity] (Uint8Array).
//   - args[2] - A function that initialises and returns a Javascript object
//     that matches the [bindings.EventModel] interface. The function must match
//     the Build function in [bindings.EventModelBuilder].
//
// Returns:
//   - Javascript representation of the [DMClient] object.
//   - Throws a TypeError if creating the manager fails.
func NewDMClient(_ js.Value, args []js.Value) any {
	privateIdentity := utils.CopyBytesToGo(args[1])

	em := &dmReceiverBuilder{args[2].Invoke}

	cm, err := bindings.NewDMClient(args[0].Int(), privateIdentity, em)
	if err != nil {
		utils.Throw(utils.TypeError, err)
		return nil
	}

	return newDMClientJS(cm)
}

// NewDMClientWithIndexedDb creates a new [DMClient] from a new
// private identity ([channel.PrivateIdentity]) and using indexedDbWorker as a backend
// to manage the event model.
//
// This function initialises an indexedDbWorker database.
//
// Parameters:
//   - args[0] - ID of [Cmix] object in tracker (int). This can be retrieved
//     using [Cmix.GetID].
//   - args[1] - Path to Javascript file that starts the worker (string).
//   - args[2] - Bytes of a private identity ([channel.PrivateIdentity]) that is
//     generated by [GenerateChannelIdentity] (Uint8Array).
//   - args[3] - Function that takes in the same parameters as
//     [indexedDbWorker.MessageReceivedCallback]. On the Javascript side, the UUID is
//     returned as an int and the channelID as a Uint8Array. The row in the
//     database that was updated can be found using the UUID. The channel ID is
//     provided so that the recipient can filter if they want to the processes
//     the update now or not. An "update" bool is present which tells you if the
//     row is new or if it is an edited old row.
//   - args[4] - ID of [ChannelDbCipher] object in tracker (int). Create this
//     object with [NewChannelsDatabaseCipher] and get its id with
//     [ChannelDbCipher.GetID].
//
// Returns a promise:
//   - Resolves to a Javascript representation of the [DMClient] object.
//   - Rejected with an error if loading indexedDbWorker or the manager fails.
//   - Throws a TypeError if the cipher ID does not correspond to a cipher.
func NewDMClientWithIndexedDb(_ js.Value, args []js.Value) any {
	cmixID := args[0].Int()
	wasmJsPath := args[1].String()
	privateIdentity := utils.CopyBytesToGo(args[2])
	messageReceivedCB := args[3]
	cipherID := args[4].Int()

	cipher, err := bindings.GetDMDbCipherTrackerFromID(cipherID)
	if err != nil {
		utils.Throw(utils.TypeError, err)
	}

	return newDMClientWithIndexedDb(
		cmixID, wasmJsPath, privateIdentity, messageReceivedCB, cipher)
}

// NewDMClientWithIndexedDbUnsafe creates a new [DMClient] from a
// new private identity ([channel.PrivateIdentity]) and using indexedDbWorker as a
// backend to manage the event model. However, the data is written in plain text
// and not encrypted. It is recommended that you do not use this in production.
//
// This function initialises an indexedDbWorker database.
//
// Parameters:
//   - args[0] - ID of [Cmix] object in tracker (int). This can be retrieved
//     using [Cmix.GetID].
//   - args[1] - Path to Javascript file that starts the worker (string).
//   - args[2] - Bytes of a private identity ([channel.PrivateIdentity]) that is
//     generated by [GenerateChannelIdentity] (Uint8Array).
//   - args[3] - Function that takes in the same parameters as
//     [indexedDbWorker.MessageReceivedCallback]. On the Javascript side, the UUID is
//     returned as an int and the channelID as a Uint8Array. The row in the
//     database that was updated can be found using the UUID. The channel ID is
//     provided so that the recipient can filter if they want to the processes
//     the update now or not. An "update" bool is present which tells you if
//     the row is new or if it is an edited old row
//
// Returns a promise:
//   - Resolves to a Javascript representation of the [DMClient] object.
//   - Rejected with an error if loading indexedDbWorker or the manager fails.
func NewDMClientWithIndexedDbUnsafe(_ js.Value, args []js.Value) any {
	cmixID := args[0].Int()
	wasmJsPath := args[1].String()
	privateIdentity := utils.CopyBytesToGo(args[2])
	messageReceivedCB := args[3]

	return newDMClientWithIndexedDb(
		cmixID, wasmJsPath, privateIdentity, messageReceivedCB, nil)
}

func newDMClientWithIndexedDb(cmixID int, wasmJsPath string,
	privateIdentity []byte, cb js.Value, cipher *bindings.DMDbCipher) any {

	messageReceivedCB := func(uuid uint64, pubKey ed25519.PublicKey,
		update bool) {
		cb.Invoke(uuid, utils.CopyBytesToJS(pubKey[:]), update)
	}

	promiseFn := func(resolve, reject func(args ...any) js.Value) {

		pi, err := codename.UnmarshalPrivateIdentity(privateIdentity)
		if err != nil {
			reject(utils.JsTrace(err))
		}
		dmPath := base64.RawStdEncoding.EncodeToString(pi.PubKey[:])
		model, err := indexDB.NewWASMEventModel(
			dmPath, wasmJsPath, cipher, messageReceivedCB)
		if err != nil {
			reject(utils.JsTrace(err))
		}

		cm, err := bindings.NewDMClientWithGoEventModel(
			cmixID, privateIdentity, model)
		if err != nil {
			reject(utils.JsTrace(err))
		} else {
			resolve(newDMClientJS(cm))
		}
	}

	return utils.CreatePromise(promiseFn)
}

////////////////////////////////////////////////////////////////////////////////
// Channel Sending Methods and Reports                                        //
////////////////////////////////////////////////////////////////////////////////

// SendGeneric is used to send a raw message over a channel. In general, it
// should be wrapped in a function which defines the wire protocol. If the final
// message, before being sent over the wire, is too long, this will return an
// error. Due to the underlying encoding using compression, it isn't possible to
// define the largest payload that can be sent, but it will always be possible
// to send a payload of 802 bytes at minimum. The meaning of validUntil depends
// on the use case.
//
// Parameters:
//   - args[0] - Marshalled bytes of the channel [id.ID] (Uint8Array).
//   - args[1] - The message type of the message. This will be a valid
//     [channels.MessageType] (int).
//   - args[2] - The contents of the message (Uint8Array).
//   - args[3] - The lease of the message. This will be how long the message is
//     valid until, in milliseconds. As per the [channels.Manager]
//     documentation, this has different meanings depending on the use case.
//     These use cases may be generic enough that they will not be enumerated
//     here (int).
//   - args[4] - JSON of [xxdk.CMIXParams]. If left empty
//     [bindings.GetDefaultCMixParams] will be used internally (Uint8Array).
//
// Returns a promise:
//   - Resolves to the JSON of [bindings.ChannelSendReport] (Uint8Array).
//   - Rejected with an error if sending fails.
func (ch *DMClient) Send(_ js.Value, args []js.Value) any {
	messageType := args[0].Int()
	partnerPubKeyBytes := utils.CopyBytesToGo(args[1])
	partnerToken := args[2].Int()
	message := utils.CopyBytesToGo(args[3])
	leaseTimeMS := int64(args[4].Int())
	cmixParamsJSON := utils.CopyBytesToGo(args[5])

	promiseFn := func(resolve, reject func(args ...any) js.Value) {
		sendReport, err := ch.api.Send(messageType, partnerPubKeyBytes,
			uint32(partnerToken), message, leaseTimeMS,
			cmixParamsJSON)
		if err != nil {
			reject(utils.JsTrace(err))
		} else {
			resolve(utils.CopyBytesToJS(sendReport))
		}
	}

	return utils.CreatePromise(promiseFn)
}

// SendMessage is used to send a formatted message over a channel.
// Due to the underlying encoding using compression, it isn't possible to define
// the largest payload that can be sent, but it will always be possible to send
// a payload of 798 bytes at minimum.
//
// The message will auto delete validUntil after the round it is sent in,
// lasting forever if [channels.ValidForever] is used.
//
// Parameters:
//   - args[0] - Marshalled bytes of the channel [id.ID] (Uint8Array).
//   - args[1] - The contents of the message (string).
//   - args[2] - The lease of the message. This will be how long the message is
//     valid until, in milliseconds. As per the [channels.Manager]
//     documentation, this has different meanings depending on the use case.
//     These use cases may be generic enough that they will not be enumerated
//     here (int).
//   - args[3] - JSON of [xxdk.CMIXParams]. If left empty
//     [bindings.GetDefaultCMixParams] will be used internally (Uint8Array).
//
// Returns a promise:
//   - Resolves to the JSON of [bindings.ChannelSendReport] (Uint8Array).
//   - Rejected with an error if sending fails.
func (ch *DMClient) SendText(_ js.Value, args []js.Value) any {
	partnerPubKeyBytes := utils.CopyBytesToGo(args[0])
	partnerToken := args[1].Int()
	message := args[2].String()
	leaseTimeMS := int64(args[3].Int())
	cmixParamsJSON := utils.CopyBytesToGo(args[4])

	promiseFn := func(resolve, reject func(args ...any) js.Value) {
		sendReport, err := ch.api.SendText(partnerPubKeyBytes,
			uint32(partnerToken), message, leaseTimeMS,
			cmixParamsJSON)
		if err != nil {
			reject(utils.JsTrace(err))
		} else {
			resolve(utils.CopyBytesToJS(sendReport))
		}
	}

	return utils.CreatePromise(promiseFn)
}

// SendReply is used to send a formatted message over a channel. Due to the
// underlying encoding using compression, it isn't possible to define the
// largest payload that can be sent, but it will always be possible to send a
// payload of 766 bytes at minimum.
//
// If the message ID the reply is sent to is nonexistent, the other side will
// post the message as a normal message and not a reply. The message will auto
// delete validUntil after the round it is sent in, lasting forever if
// [channels.ValidForever] is used.
//
// Parameters:
//   - args[0] - Marshalled bytes of the channel [id.ID] (Uint8Array).
//   - args[1] - The contents of the message. The message should be at most 510
//     bytes. This is expected to be Unicode, and thus a string data type is
//     expected (string).
//   - args[2] - JSON of [channel.MessageID] of the message you wish to reply
//     to. This may be found in the [bindings.ChannelSendReport] if replying to
//     your own. Alternatively, if reacting to another user's message, you may
//     retrieve it via the [bindings.ChannelMessageReceptionCallback] registered
//     using  RegisterReceiveHandler (Uint8Array).
//   - args[3] - The lease of the message. This will be how long the message is
//     valid until, in milliseconds. As per the [channels.Manager]
//     documentation, this has different meanings depending on the use case.
//     These use cases may be generic enough that they will not be enumerated
//     here (int).
//   - args[4] - JSON of [xxdk.CMIXParams]. If left empty
//     [bindings.GetDefaultCMixParams] will be used internally (Uint8Array).
//
// Returns a promise:
//   - Resolves to the JSON of [bindings.ChannelSendReport] (Uint8Array).
//   - Rejected with an error if sending fails.
func (ch *DMClient) SendReply(_ js.Value, args []js.Value) any {
	partnerPubKeyBytes := utils.CopyBytesToGo(args[0])
	partnerToken := args[1].Int()
	replyID := utils.CopyBytesToGo(args[2])
	message := args[3].String()
	leaseTimeMS := int64(args[4].Int())
	cmixParamsJSON := utils.CopyBytesToGo(args[5])

	promiseFn := func(resolve, reject func(args ...any) js.Value) {
		sendReport, err := ch.api.SendReply(partnerPubKeyBytes,
			uint32(partnerToken), message, replyID, leaseTimeMS,
			cmixParamsJSON)
		if err != nil {
			reject(utils.JsTrace(err))
		} else {
			resolve(utils.CopyBytesToJS(sendReport))
		}
	}

	return utils.CreatePromise(promiseFn)
}

// SendReaction is used to send a reaction to a message over a channel.
// The reaction must be a single emoji with no other characters, and will
// be rejected otherwise.
// Users will drop the reaction if they do not recognize the reactTo message.
//
// Parameters:
//   - args[0] - Marshalled bytes of the channel [id.ID] (Uint8Array).
//   - args[1] - The user's reaction. This should be a single emoji with no
//     other characters. As such, a Unicode string is expected (string).
//   - args[2] - JSON of [channel.MessageID] of the message you wish to reply
//     to. This may be found in the [bindings.ChannelSendReport] if replying to
//     your own. Alternatively, if reacting to another user's message, you may
//     retrieve it via the ChannelMessageReceptionCallback registered using
//     RegisterReceiveHandler (Uint8Array).
//   - args[3] - JSON of [xxdk.CMIXParams]. If left empty
//     [bindings.GetDefaultCMixParams] will be used internally (Uint8Array).
//
// Returns a promise:
//   - Resolves to the JSON of [bindings.ChannelSendReport] (Uint8Array).
//   - Rejected with an error if sending fails.
func (ch *DMClient) SendReaction(_ js.Value, args []js.Value) any {
	partnerPubKeyBytes := utils.CopyBytesToGo(args[0])
	partnerToken := args[1].Int()
	replyID := utils.CopyBytesToGo(args[2])
	message := args[3].String()
	cmixParamsJSON := utils.CopyBytesToGo(args[4])

	promiseFn := func(resolve, reject func(args ...any) js.Value) {
		sendReport, err := ch.api.SendReaction(partnerPubKeyBytes,
			uint32(partnerToken), message, replyID,
			cmixParamsJSON)
		if err != nil {
			reject(utils.JsTrace(err))
		} else {
			resolve(utils.CopyBytesToJS(sendReport))
		}
	}

	return utils.CreatePromise(promiseFn)
}

// GetIdentity returns the marshaled public identity ([codename.Identity]) that
// the client is using.
//
// Returns:
//   - JSON of the [channel.Identity] (Uint8Array).
//   - Throws TypeError if marshalling the identity fails.
func (ch *DMClient) GetIdentity(js.Value, []js.Value) any {
	i := ch.api.GetIdentity()

	return utils.CopyBytesToJS(i)
}

// ExportPrivateIdentity encrypts and exports the private identity to a portable
// string.
//
// Parameters:
//   - args[0] - Password to encrypt the identity with (string).
//
// Returns:
//   - JSON of the encrypted private identity (Uint8Array).
//   - Throws TypeError if exporting the identity fails.
func (ch *DMClient) ExportPrivateIdentity(_ js.Value, args []js.Value) any {
	i, err := ch.api.ExportPrivateIdentity(args[0].String())
	if err != nil {
		utils.Throw(utils.TypeError, err)
		return nil
	}

	return utils.CopyBytesToJS(i)
}

// SetNickname sets the nickname for a given channel. The nickname must be valid
// according to [IsNicknameValid].
//
// Parameters:
//   - args[0] - The nickname to set (string).
//   - args[1] - Marshalled bytes if the channel's [id.ID] (Uint8Array).
//
// Returns:
//   - Throws TypeError if unmarshalling the ID fails or the nickname is
//     invalid.
func (ch *DMClient) SetNickname(_ js.Value, args []js.Value) any {
	ch.api.SetNickname(args[0].String())
	return nil
}

// GetNickname returns the nickname set for a given channel. Returns an error if
// there is no nickname set.
//
// Parameters:
//   - args[0] - Marshalled bytes if the channel's [id.ID] (Uint8Array).
//
// Returns:
//   - The nickname (string).
//   - Throws TypeError if the channel has no nickname set.
func (ch *DMClient) GetNickname(_ js.Value, args []js.Value) any {
	nickname, err := ch.api.GetNickname(utils.CopyBytesToGo(args[0]))
	if err != nil {
		utils.Throw(utils.TypeError, err)
		return nil
	}

	return nickname
}

// GetDatabaseName returns the storage tag, so users listening to the database
// can separately listen and read updates there.
//
// Parameters:
//
// Returns:
//   - The storage tag (string).
func (dmc *DMClient) GetDatabaseName(_ js.Value, args []js.Value) any {
	return (base64.RawStdEncoding.EncodeToString(dmc.api.GetPublicKey()) +
		"_speakeasy_dm")
}

////////////////////////////////////////////////////////////////////////////////
// Channel Receiving Logic and Callback Registration                          //
////////////////////////////////////////////////////////////////////////////////

// channelMessageReceptionCallback wraps Javascript callbacks to adhere to the
// [bindings.ChannelMessageReceptionCallback] interface.
type dmReceptionCallback struct {
	callback func(args ...any) js.Value
}

// Callback returns the context for a channel message.
//
// Parameters:
//   - receivedChannelMessageReport - Returns the JSON of
//     [bindings.ReceivedChannelMessageReport] (Uint8Array).
//   - err - Returns an error on failure (Error).
//
// Returns:
//   - It must return a unique UUID for the message that it can be referenced by
//     later (int).
func (cmrCB *dmReceptionCallback) Callback(
	receivedChannelMessageReport []byte, err error) int {
	uuid := cmrCB.callback(
		utils.CopyBytesToJS(receivedChannelMessageReport),
		utils.JsTrace(err))

	return uuid.Int()
}

////////////////////////////////////////////////////////////////////////////////
// Event Model Logic                                                          //
////////////////////////////////////////////////////////////////////////////////

// dmReceiver wraps Javascript callbacks to adhere to the [bindings.EventModel]
// interface.
type dmReceiver struct {
	receive          func(args ...any) js.Value
	receiveText      func(args ...any) js.Value
	receiveReply     func(args ...any) js.Value
	receiveReaction  func(args ...any) js.Value
	updateSentStatus func(args ...any) js.Value
}

// ReceiveMessage is called whenever a message is received on a given channel.
// It may be called multiple times on the same message. It is incumbent on the
// user of the API to filter such called by message ID.
//
// Parameters:
//   - channelID - Marshalled bytes of the channel [id.ID] (Uint8Array).
//   - messageID - The bytes of the [channel.MessageID] of the received message
//     (Uint8Array).
//   - nickname - The nickname of the sender of the message (string).
//   - text - The content of the message (string).
//   - pubKey - The sender's Ed25519 public key (Uint8Array).
//   - dmToken - The dmToken (int32).
//   - codeset - The codeset version (int).
//   - timestamp - Time the message was received; represented as nanoseconds
//     since unix epoch (int).
//   - lease - The number of nanoseconds that the message is valid for (int).
//   - roundId - The ID of the round that the message was received on (int).
//   - msgType - The type of message ([channels.MessageType]) to send (int).
//   - status - The [channels.SentStatus] of the message (int).
//
// Statuses will be enumerated as such:
//
//	Sent      =  0
//	Delivered =  1
//	Failed    =  2
//
// Returns:
//   - A non-negative unique UUID for the message that it can be referenced by
//     later with [dmReceiver.UpdateSentStatus].
func (em *dmReceiver) Receive(messageID []byte, nickname string,
	text []byte, partnerKey, senderKey []byte, dmToken int32, codeset int, timestamp,
	roundId, mType, status int64) int64 {
	uuid := em.receive(messageID, nickname, text, partnerKey, senderKey, dmToken,
		codeset, timestamp, roundId, mType, status)

	return int64(uuid.Int())
}

// ReceiveText is called whenever a message is received that is a reply on a
// given channel. It may be called multiple times on the same message. It is
// incumbent on the user of the API to filter such called by message ID.
//
// Messages may arrive our of order, so a reply in theory can arrive before the
// initial message. As a result, it may be important to buffer replies.
//
// Parameters:
//   - channelID - Marshalled bytes of the channel [id.ID] (Uint8Array).
//   - messageID - The bytes of the [channel.MessageID] of the received message
//     (Uint8Array).
//   - reactionTo - The [channel.MessageID] for the message that received a
//     reply (Uint8Array).
//   - senderUsername - The username of the sender of the message (string).
//   - text - The content of the message (string).
//   - partnerKey, senderKey - The sender's Ed25519 public key (Uint8Array).
//   - dmToken - The dmToken (int32).
//   - codeset - The codeset version (int).
//   - timestamp - Time the message was received; represented as nanoseconds
//     since unix epoch (int).
//   - lease - The number of nanoseconds that the message is valid for (int).
//   - roundId - The ID of the round that the message was received on (int).
//   - msgType - The type of message ([channels.MessageType]) to send (int).
//   - status - The [channels.SentStatus] of the message (int).
//
// Statuses will be enumerated as such:
//
//	Sent      =  0
//	Delivered =  1
//	Failed    =  2
//
// Returns:
//   - A non-negative unique UUID for the message that it can be referenced by
//     later with [dmReceiver.UpdateSentStatus].
func (em *dmReceiver) ReceiveText(messageID []byte, nickname, text string,
	partnerKey, senderKey []byte, dmToken int32, codeset int, timestamp,
	roundId, status int64) int64 {

	uuid := em.receiveText(messageID, nickname, text, partnerKey, senderKey, dmToken,
		codeset, timestamp, roundId, status)

	return int64(uuid.Int())
}

// ReceiveReply is called whenever a message is received that is a reply on a
// given channel. It may be called multiple times on the same message. It is
// incumbent on the user of the API to filter such called by message ID.
//
// Messages may arrive our of order, so a reply in theory can arrive before the
// initial message. As a result, it may be important to buffer replies.
//
// Parameters:
//   - channelID - Marshalled bytes of the channel [id.ID] (Uint8Array).
//   - messageID - The bytes of the [channel.MessageID] of the received message
//     (Uint8Array).
//   - reactionTo - The [channel.MessageID] for the message that received a
//     reply (Uint8Array).
//   - senderUsername - The username of the sender of the message (string).
//   - text - The content of the message (string).
//   - partnerKey, senderKey - The sender's Ed25519 public key (Uint8Array).
//   - dmToken - The dmToken (int32).
//   - codeset - The codeset version (int).
//   - timestamp - Time the message was received; represented as nanoseconds
//     since unix epoch (int).
//   - lease - The number of nanoseconds that the message is valid for (int).
//   - roundId - The ID of the round that the message was received on (int).
//   - msgType - The type of message ([channels.MessageType]) to send (int).
//   - status - The [channels.SentStatus] of the message (int).
//
// Statuses will be enumerated as such:
//
//	Sent      =  0
//	Delivered =  1
//	Failed    =  2
//
// Returns:
//   - A non-negative unique UUID for the message that it can be referenced by
//     later with [dmReceiver.UpdateSentStatus].
func (em *dmReceiver) ReceiveReply(messageID, replyTo []byte, nickname,
	text string, partnerKey, senderKey []byte, dmToken int32, codeset int,
	timestamp, roundId, status int64) int64 {
	uuid := em.receiveReply(messageID, replyTo, nickname, text, partnerKey, senderKey,
		dmToken, codeset, timestamp, roundId, status)

	return int64(uuid.Int())
}

// ReceiveReaction is called whenever a reaction to a message is received on a
// given channel. It may be called multiple times on the same reaction. It is
// incumbent on the user of the API to filter such called by message ID.
//
// Messages may arrive our of order, so a reply in theory can arrive before the
// initial message. As a result, it may be important to buffer reactions.
//
// Parameters:
//   - channelID - Marshalled bytes of the channel [id.ID] (Uint8Array).
//   - messageID - The bytes of the [channel.MessageID] of the received message
//     (Uint8Array).
//   - reactionTo - The [channel.MessageID] for the message that received a
//     reply (Uint8Array).
//   - senderUsername - The username of the sender of the message (string).
//   - reaction - The contents of the reaction message (string).
//   - partnerKey, senderKey - The sender's Ed25519 public key (Uint8Array).
//   - dmToken - The dmToken (int32).
//   - codeset - The codeset version (int).
//   - timestamp - Time the message was received; represented as nanoseconds
//     since unix epoch (int).
//   - lease - The number of nanoseconds that the message is valid for (int).
//   - roundId - The ID of the round that the message was received on (int).
//   - msgType - The type of message ([channels.MessageType]) to send (int).
//   - status - The [channels.SentStatus] of the message (int).
//
// Statuses will be enumerated as such:
//
//	Sent      =  0
//	Delivered =  1
//	Failed    =  2
//
// Returns:
//   - A non-negative unique UUID for the message that it can be referenced by
//     later with [dmReceiver.UpdateSentStatus].
func (em *dmReceiver) ReceiveReaction(messageID, reactionTo []byte,
	nickname, reaction string, partnerKey, senderKey []byte, dmToken int32,
	codeset int, timestamp, roundId,
	status int64) int64 {
	uuid := em.receiveReaction(messageID, reactionTo, nickname, reaction,
		partnerKey, senderKey, dmToken, codeset, timestamp, roundId, status)

	return int64(uuid.Int())
}

// UpdateSentStatus is called whenever the sent status of a message has
// changed.
//
// Parameters:
//   - uuid - The unique identifier for the message (int).
//   - messageID - The bytes of the [channel.MessageID] of the received message
//     (Uint8Array).
//   - timestamp - Time the message was received; represented as nanoseconds
//     since unix epoch (int).
//   - roundId - The ID of the round that the message was received on (int).
//   - status - The [channels.SentStatus] of the message (int).
//
// Statuses will be enumerated as such:
//
//	Sent      =  0
//	Delivered =  1
//	Failed    =  2
func (em *dmReceiver) UpdateSentStatus(uuid int64, messageID []byte,
	timestamp, roundID, status int64) {
	em.updateSentStatus(uuid, utils.CopyBytesToJS(messageID),
		timestamp, roundID, status)
}

////////////////////////////////////////////////////////////////////////////////
// DM DB Cipher                                                               //
////////////////////////////////////////////////////////////////////////////////

// DMDbCipher wraps the [bindings.DMDbCipher] object so its methods
// can be wrapped to be Javascript compatible.
type DMDbCipher struct {
	api *bindings.DMDbCipher
}

// newDMDbCipherJS creates a new Javascript compatible object
// (map[string]any) that matches the [DMDbCipher] structure.
func newDMDbCipherJS(api *bindings.DMDbCipher) map[string]any {
	c := DMDbCipher{api}
	channelDbCipherMap := map[string]any{
		"GetID":         js.FuncOf(c.GetID),
		"Encrypt":       js.FuncOf(c.Encrypt),
		"Decrypt":       js.FuncOf(c.Decrypt),
		"MarshalJSON":   js.FuncOf(c.MarshalJSON),
		"UnmarshalJSON": js.FuncOf(c.UnmarshalJSON),
	}

	return channelDbCipherMap
}

// NewDMsDatabaseCipher constructs a [DMDbCipher] object.
//
// Parameters:
//   - args[0] - The tracked [Cmix] object ID (int).
//   - args[1] - The password for storage. This should be the same password
//     passed into [NewCmix] (Uint8Array).
//   - args[2] - The maximum size of a payload to be encrypted. A payload passed
//     into [DMDbCipher.Encrypt] that is larger than this value will result
//     in an error (int).
//
// Returns:
//   - JavaScript representation of the [DMDbCipher] object.
//   - Throws a TypeError if creating the cipher fails.
func NewDMsDatabaseCipher(_ js.Value, args []js.Value) any {
	cmixId := args[0].Int()
	password := utils.CopyBytesToGo(args[1])
	plaintTextBlockSize := args[2].Int()

	cipher, err := bindings.NewDMsDatabaseCipher(
		cmixId, password, plaintTextBlockSize)
	if err != nil {
		utils.Throw(utils.TypeError, err)
		return nil
	}

	return newDMDbCipherJS(cipher)
}

// GetID returns the ID for this [bindings.DMDbCipher] in the
// channelDbCipherTracker.
//
// Returns:
//   - Tracker ID (int).
func (c *DMDbCipher) GetID(js.Value, []js.Value) any {
	return c.api.GetID()
}

// Encrypt will encrypt the raw data. It will return a ciphertext. Padding is
// done on the plaintext so all encrypted data looks uniform at rest.
//
// Parameters:
//   - args[0] - The data to be encrypted (Uint8Array). This must be smaller
//     than the block size passed into [NewDMsDatabaseCipher]. If it is
//     larger, this will return an error.
//
// Returns:
//   - The ciphertext of the plaintext passed in (Uint8Array).
//   - Throws a TypeError if it fails to encrypt the plaintext.
func (c *DMDbCipher) Encrypt(_ js.Value, args []js.Value) any {
	ciphertext, err := c.api.Encrypt(utils.CopyBytesToGo(args[0]))
	if err != nil {
		utils.Throw(utils.TypeError, err)
		return nil
	}

	return utils.CopyBytesToJS(ciphertext)
}

// Decrypt will decrypt the passed in encrypted value. The plaintext will be
// returned by this function. Any padding will be discarded within this
// function.
//
// Parameters:
//   - args[0] - the encrypted data returned by [DMDbCipher.Encrypt]
//     (Uint8Array).
//
// Returns:
//   - The plaintext of the ciphertext passed in (Uint8Array).
//   - Throws a TypeError if it fails to encrypt the plaintext.
func (c *DMDbCipher) Decrypt(_ js.Value, args []js.Value) any {
	plaintext, err := c.api.Decrypt(utils.CopyBytesToGo(args[0]))
	if err != nil {
		utils.Throw(utils.TypeError, err)
		return nil
	}

	return utils.CopyBytesToJS(plaintext)
}

// MarshalJSON marshals the cipher into valid JSON.
//
// Returns:
//   - JSON of the cipher (Uint8Array).
//   - Throws a TypeError if marshalling fails.
func (c *DMDbCipher) MarshalJSON(js.Value, []js.Value) any {
	data, err := c.api.MarshalJSON()
	if err != nil {
		utils.Throw(utils.TypeError, err)
		return nil
	}

	return utils.CopyBytesToJS(data)
}

// UnmarshalJSON unmarshalls JSON into the cipher. This function adheres to the
// json.Unmarshaler interface.
//
// Note that this function does not transfer the internal RNG. Use
// [channel.NewCipherFromJSON] to properly reconstruct a cipher from JSON.
//
// Parameters:
//   - args[0] - JSON data to unmarshal (Uint8Array).
//
// Returns:
//   - JSON of the cipher (Uint8Array).
//   - Throws a TypeError if marshalling fails.
func (c *DMDbCipher) UnmarshalJSON(_ js.Value, args []js.Value) any {
	err := c.api.UnmarshalJSON(utils.CopyBytesToGo(args[0]))
	if err != nil {
		utils.Throw(utils.TypeError, err)
		return nil
	}
	return nil
}
