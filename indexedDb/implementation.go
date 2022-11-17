////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

//go:build js && wasm

package indexedDb

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"sync"
	"syscall/js"
	"time"

	"github.com/hack-pad/go-indexeddb/idb"
	"github.com/pkg/errors"
	jww "github.com/spf13/jwalterweatherman"

	"gitlab.com/elixxir/client/channels"
	"gitlab.com/elixxir/client/cmix/rounds"
	cryptoBroadcast "gitlab.com/elixxir/crypto/broadcast"
	cryptoChannel "gitlab.com/elixxir/crypto/channel"
	"gitlab.com/elixxir/xxdk-wasm/utils"
	"gitlab.com/xx_network/primitives/id"
)

// dbTimeout is the global timeout for operations with the storage
// [context.Context].
const dbTimeout = time.Second

// wasmModel implements [channels.EventModel] interface, which uses the channels
// system passed an object that adheres to in order to get events on the
// channel.
type wasmModel struct {
	db                *idb.Database
	cipher            cryptoChannel.Cipher
	receivedMessageCB MessageReceivedCallback
	updateMux         sync.Mutex
}

// newContext builds a context for database operations.
func newContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), dbTimeout)
}

// JoinChannel is called whenever a channel is joined locally.
func (w *wasmModel) JoinChannel(channel *cryptoBroadcast.Channel) {
	parentErr := errors.New("failed to JoinChannel")

	// Build object
	newChannel := Channel{
		ID:          channel.ReceptionID.Marshal(),
		Name:        channel.Name,
		Description: channel.Description,
	}

	// Convert to jsObject
	newChannelJson, err := json.Marshal(&newChannel)
	if err != nil {
		jww.ERROR.Printf("%+v", errors.WithMessagef(parentErr,
			"Unable to marshal Channel: %+v", err))
		return
	}
	channelObj, err := utils.JsonToJS(newChannelJson)
	if err != nil {
		jww.ERROR.Printf("%+v", errors.WithMessagef(parentErr,
			"Unable to marshal Channel: %+v", err))
		return
	}

	// Prepare the Transaction
	txn, err := w.db.Transaction(idb.TransactionReadWrite, channelsStoreName)
	if err != nil {
		jww.ERROR.Printf("%+v", errors.WithMessagef(parentErr,
			"Unable to create Transaction: %+v", err))
		return
	}
	store, err := txn.ObjectStore(channelsStoreName)
	if err != nil {
		jww.ERROR.Printf("%+v", errors.WithMessagef(parentErr,
			"Unable to get ObjectStore: %+v", err))
		return
	}

	// Perform the operation
	_, err = store.Put(channelObj)
	if err != nil {
		jww.ERROR.Printf("%+v", errors.WithMessagef(parentErr,
			"Unable to Add Channel: %+v", err))
		return
	}

	// Wait for the operation to return
	ctx, cancel := newContext()
	err = txn.Await(ctx)
	cancel()
	if err != nil {
		jww.ERROR.Printf("%+v", errors.WithMessagef(parentErr,
			"Adding Channel failed: %+v", err))
		return
	}
	jww.DEBUG.Printf("Successfully added channel: %s", channel.ReceptionID)
}

// LeaveChannel is called whenever a channel is left locally.
func (w *wasmModel) LeaveChannel(channelID *id.ID) {
	parentErr := errors.New("failed to LeaveChannel")

	// Prepare the Transaction
	txn, err := w.db.Transaction(idb.TransactionReadWrite, channelsStoreName)
	if err != nil {
		jww.ERROR.Printf("%+v", errors.WithMessagef(parentErr,
			"Unable to create Transaction: %+v", err))
		return
	}
	store, err := txn.ObjectStore(channelsStoreName)
	if err != nil {
		jww.ERROR.Printf("%+v", errors.WithMessagef(parentErr,
			"Unable to get ObjectStore: %+v", err))
		return
	}

	// Perform the operation
	_, err = store.Delete(js.ValueOf(channelID.String()))
	if err != nil {
		jww.ERROR.Printf("%+v", errors.WithMessagef(parentErr,
			"Unable to Delete Channel: %+v", err))
		return
	}

	// Wait for the operation to return
	ctx, cancel := newContext()
	err = txn.Await(ctx)
	cancel()
	if err != nil {
		jww.ERROR.Printf("%+v", errors.WithMessagef(parentErr,
			"Deleting Channel failed: %+v", err))
		return
	}

	// Clean up lingering data
	err = w.deleteMsgByChannel(channelID)
	if err != nil {
		jww.ERROR.Printf("%+v", errors.WithMessagef(parentErr,
			"Deleting Channel's Message data failed: %+v", err))
		return
	}
	jww.DEBUG.Printf("Successfully deleted channel: %s", channelID)
}

// deleteMsgByChannel is a private helper that uses messageStoreChannelIndex
// to delete all Message with the given Channel ID.
func (w *wasmModel) deleteMsgByChannel(channelID *id.ID) error {
	parentErr := errors.New("failed to deleteMsgByChannel")

	// Prepare the Transaction
	txn, err := w.db.Transaction(idb.TransactionReadWrite, messageStoreName)
	if err != nil {
		return errors.WithMessagef(parentErr,
			"Unable to create Transaction: %+v", err)
	}
	store, err := txn.ObjectStore(messageStoreName)
	if err != nil {
		return errors.WithMessagef(parentErr,
			"Unable to get ObjectStore: %+v", err)
	}
	index, err := store.Index(messageStoreChannelIndex)
	if err != nil {
		return errors.WithMessagef(parentErr,
			"Unable to get Index: %+v", err)
	}

	// Perform the operation
	channelIdStr := base64.StdEncoding.EncodeToString(channelID.Marshal())
	keyRange, err := idb.NewKeyRangeOnly(js.ValueOf(channelIdStr))
	cursorRequest, err := index.OpenCursorRange(keyRange, idb.CursorNext)
	if err != nil {
		return errors.WithMessagef(parentErr, "Unable to open Cursor: %+v", err)
	}
	ctx, cancel := newContext()
	err = cursorRequest.Iter(ctx,
		func(cursor *idb.CursorWithValue) error {
			_, err := cursor.Delete()
			return err
		})
	cancel()
	if err != nil {
		return errors.WithMessagef(parentErr,
			"Unable to delete Message data: %+v", err)
	}
	return nil
}

// ReceiveMessage is called whenever a message is received on a given channel.
//
// It may be called multiple times on the same message; it is incumbent on the
// user of the API to filter such called by message ID.
func (w *wasmModel) ReceiveMessage(channelID *id.ID,
	messageID cryptoChannel.MessageID, nickname, text string,
	pubKey ed25519.PublicKey, codeset uint8,
	timestamp time.Time, lease time.Duration, round rounds.Round,
	mType channels.MessageType, status channels.SentStatus, hidden bool) uint64 {
	textBytes := []byte(text)
	var err error

	// Handle encryption, if it is present
	if w.cipher != nil {
		textBytes, err = w.cipher.Encrypt([]byte(text))
		if err != nil {
			jww.ERROR.Printf("Failed to encrypt Message: %+v", err)
			return 0
		}
	}

	msgToInsert := buildMessage(
		channelID.Marshal(), messageID.Bytes(), nil, nickname,
		textBytes, pubKey, codeset, timestamp, lease, round.ID, mType,
		false, hidden, status)

	uuid, err := w.receiveHelper(msgToInsert, false)
	if err != nil {
		jww.ERROR.Printf("Failed to receive Message: %+v", err)
	}

	go w.receivedMessageCB(uuid, channelID, false)
	return uuid
}

// ReceiveReply is called whenever a message is received that is a reply on a
// given channel. It may be called multiple times on the same message; it is
// incumbent on the user of the API to filter such called by message ID.
//
// Messages may arrive our of order, so a reply, in theory, can arrive before
// the initial message. As a result, it may be important to buffer replies.
func (w *wasmModel) ReceiveReply(channelID *id.ID,
	messageID cryptoChannel.MessageID, replyTo cryptoChannel.MessageID,
	nickname, text string, pubKey ed25519.PublicKey, codeset uint8,
	timestamp time.Time, lease time.Duration, round rounds.Round,
	mType channels.MessageType, status channels.SentStatus, hidden bool) uint64 {
	textBytes := []byte(text)
	var err error

	// Handle encryption, if it is present
	if w.cipher != nil {
		textBytes, err = w.cipher.Encrypt([]byte(text))
		if err != nil {
			jww.ERROR.Printf("Failed to encrypt Message: %+v", err)
			return 0
		}
	}

	msgToInsert := buildMessage(channelID.Marshal(), messageID.Bytes(),
		replyTo.Bytes(), nickname, textBytes, pubKey, codeset, timestamp, lease,
		round.ID, mType, false, hidden, status)

	uuid, err := w.receiveHelper(msgToInsert, false)

	if err != nil {
		jww.ERROR.Printf("Failed to receive reply: %+v", err)
	}
	go w.receivedMessageCB(uuid, channelID, false)
	return uuid
}

// ReceiveReaction is called whenever a reaction to a message is received on a
// given channel. It may be called multiple times on the same reaction; it is
// incumbent on the user of the API to filter such called by message ID.
//
// Messages may arrive our of order, so a reply, in theory, can arrive before
// the initial message. As a result, it may be important to buffer reactions.
func (w *wasmModel) ReceiveReaction(channelID *id.ID,
	messageID cryptoChannel.MessageID, reactionTo cryptoChannel.MessageID,
	nickname, reaction string, pubKey ed25519.PublicKey, codeset uint8,
	timestamp time.Time, lease time.Duration, round rounds.Round,
	mType channels.MessageType, status channels.SentStatus, hidden bool) uint64 {
	textBytes := []byte(reaction)
	var err error

	// Handle encryption, if it is present
	if w.cipher != nil {
		textBytes, err = w.cipher.Encrypt([]byte(reaction))
		if err != nil {
			jww.ERROR.Printf("Failed to encrypt Message: %+v", err)
			return 0
		}
	}

	msgToInsert := buildMessage(
		channelID.Marshal(), messageID.Bytes(), reactionTo.Bytes(), nickname,
		textBytes, pubKey, codeset, timestamp, lease, round.ID, mType,
		false, hidden, status)

	uuid, err := w.receiveHelper(msgToInsert, false)
	if err != nil {
		jww.ERROR.Printf("Failed to receive reaction: %+v", err)
	}
	go w.receivedMessageCB(uuid, channelID, false)
	return uuid
}

// UpdateFromMessageID is called whenever a message with the message ID is
// modified.
//
// The API needs to return the UUID of the modified message that can be
// referenced at a later time.
//
// timestamp, round, pinned, and hidden are all nillable and may be updated
// based upon the UUID at a later date. If a nil value is passed, then make
// no update.
func (w *wasmModel) UpdateFromMessageID(messageID cryptoChannel.MessageID,
	timestamp *time.Time, round *rounds.Round, pinned, hidden *bool,
	status *channels.SentStatus) uint64 {
	parentErr := errors.New("failed to UpdateFromMessageID")

	// FIXME: this is a bit of race condition without the mux.
	//        This should be done via the transactions (i.e., make a
	//        special version of receiveHelper)
	w.updateMux.Lock()
	defer w.updateMux.Unlock()

	msgIDStr := base64.StdEncoding.EncodeToString(messageID.Marshal())
	currentMsgObj, err := w.getIndex(messageStoreName,
		messageStoreMessageIndex, js.ValueOf(msgIDStr))
	if err != nil {
		jww.ERROR.Printf("%+v", errors.WithMessagef(parentErr,
			"Failed to get message by index: %+v", err))
		return 0
	}

	currentMsg := utils.JsToJson(currentMsgObj)
	uuid, err := w.updateMessage(currentMsg, &messageID, timestamp,
		round, pinned, hidden, status)
	if err != nil {
		jww.ERROR.Printf("%+v", errors.WithMessagef(parentErr,
			"Unable to updateMessage: %+v", err))
	}
	return uuid
}

// messageID, timestamp, round, pinned, and hidden are all nillable and may
// be updated based upon the UUID at a later date. If a nil value is passed,
// then make no update.
func (w *wasmModel) UpdateFromUUID(uuid uint64, messageID *cryptoChannel.MessageID,
	timestamp *time.Time, round *rounds.Round, pinned, hidden *bool,
	status *channels.SentStatus) {
	parentErr := errors.New("failed to UpdateFromUUID")

	// FIXME: this is a bit of race condition without the mux.
	//        This should be done via the transactions (i.e., make a
	//        special version of receiveHelper)
	w.updateMux.Lock()
	defer w.updateMux.Unlock()

	// Convert messageID to the key generated by json.Marshal
	key := js.ValueOf(uuid)

	// Use the key to get the existing Message
	currentMsg, err := w.get(messageStoreName, key)
	if err != nil {
		jww.ERROR.Printf("%+v", errors.WithMessagef(parentErr,
			"Failed to get message: %+v", err))
		return
	}

	_, err = w.updateMessage(currentMsg, messageID, timestamp,
		round, pinned, hidden, status)
	if err != nil {
		jww.ERROR.Printf("%+v", errors.WithMessagef(parentErr,
			"Unable to updateMessage: %+v", err))
	}
}

// updateMessage is a helper for updating a stored message.
func (w *wasmModel) updateMessage(currentMsgJson string,
	messageID *cryptoChannel.MessageID, timestamp *time.Time,
	round *rounds.Round, pinned, hidden *bool,
	status *channels.SentStatus) (uint64, error) {

	newMessage := &Message{}
	err := json.Unmarshal([]byte(currentMsgJson), newMessage)
	if err != nil {
		return 0, nil
	}

	if status != nil {
		newMessage.Status = uint8(*status)
	}
	if messageID != nil {
		newMessage.MessageID = messageID.Marshal()
	}

	if round != nil {
		newMessage.Round = uint64(round.ID)
	}

	if timestamp != nil {
		newMessage.Timestamp = *timestamp
	}

	if pinned != nil {
		newMessage.Pinned = *pinned
	}

	if hidden != nil {
		newMessage.Hidden = *hidden
	}

	// Store the updated Message
	uuid, err := w.receiveHelper(newMessage, true)
	if err != nil {
		return 0, err
	}
	channelID := &id.ID{}
	copy(channelID[:], newMessage.ChannelID)
	go w.receivedMessageCB(uuid, channelID, true)

	return uuid, nil
}

// buildMessage is a private helper that converts typical [channels.EventModel]
// inputs into a basic Message structure for insertion into storage.
//
// NOTE: ID is not set inside this function because we want to use the
// autoincrement key by default. If you are trying to overwrite an existing
// message, then you need to set it manually yourself.
func buildMessage(channelID, messageID, parentID []byte, nickname string,
	text []byte, pubKey ed25519.PublicKey, codeset uint8, timestamp time.Time,
	lease time.Duration, round id.Round, mType channels.MessageType,
	pinned, hidden bool, status channels.SentStatus) *Message {
	return &Message{
		MessageID:       messageID,
		Nickname:        nickname,
		ChannelID:       channelID,
		ParentMessageID: parentID,
		Timestamp:       timestamp,
		Lease:           lease,
		Status:          uint8(status),
		Hidden:          hidden,
		Pinned:          pinned,
		Text:            text,
		Type:            uint16(mType),
		Round:           uint64(round),
		// User Identity Info
		Pubkey:         pubKey,
		CodesetVersion: codeset,
	}
}

// receiveHelper is a private helper for receiving any sort of message.
func (w *wasmModel) receiveHelper(newMessage *Message, isUpdate bool) (uint64,
	error) {
	// Convert to jsObject
	newMessageJson, err := json.Marshal(newMessage)
	if err != nil {
		return 0, errors.Errorf("Unable to marshal Message: %+v", err)
	}
	messageObj, err := utils.JsonToJS(newMessageJson)
	if err != nil {
		return 0, errors.Errorf("Unable to marshal Message: %+v", err)
	}

	// Unset the primaryKey for inserts so that it can be auto-populated and
	// incremented
	if !isUpdate {
		messageObj.Delete("id")
	}

	// Prepare the Transaction
	txn, err := w.db.Transaction(idb.TransactionReadWrite, messageStoreName)
	if err != nil {
		return 0, errors.Errorf("Unable to create Transaction: %+v",
			err)
	}
	store, err := txn.ObjectStore(messageStoreName)
	if err != nil {
		return 0, errors.Errorf("Unable to get ObjectStore: %+v", err)
	}

	// Perform the upsert (put) operation
	addReq, err := store.Put(messageObj)
	if err != nil {
		return 0, errors.Errorf("Unable to upsert Message: %+v", err)
	}

	// Wait for the operation to return
	ctx, cancel := newContext()
	err = txn.Await(ctx)
	cancel()
	if err != nil {
		return 0, errors.Errorf("Upserting Message failed: %+v", err)
	}
	res, err := addReq.Result()

	// NOTE: Sometimes the insert fails to return an error but hits a duplicate
	//  insert, so this fallthrough returns the UUID entry in that case.
	if res.IsUndefined() {
		msgID := cryptoChannel.MessageID{}
		copy(msgID[:], newMessage.MessageID)
		msg, errLookup := w.msgIDLookup(msgID)
		if msg.ID != 0 && errLookup == nil {
			return msg.ID, nil
		}
		return 0, errors.Errorf("uuid lookup failure: %+v", err)
	}
	uuid := uint64(res.Int())
	jww.DEBUG.Printf("Successfully stored message %d", uuid)

	return uuid, nil
}

// GetMessage returns the message with the given [channel.MessageID].
func (w *wasmModel) GetMessage(messageID cryptoChannel.MessageID) (channels.ModelMessage, error) {
	lookupResult, err := w.msgIDLookup(messageID)
	if err != nil {
		return channels.ModelMessage{}, err
	}

	var channelId *id.ID
	if lookupResult.ChannelID != nil {
		channelId, err = id.Unmarshal(lookupResult.ChannelID)
		if err != nil {
			return channels.ModelMessage{}, err
		}
	}

	var parentMsgId cryptoChannel.MessageID
	if lookupResult.ParentMessageID != nil {
		parentMsgId, err = cryptoChannel.UnmarshalMessageID(lookupResult.ParentMessageID)
		if err != nil {
			return channels.ModelMessage{}, err
		}
	}

	return channels.ModelMessage{
		UUID:            lookupResult.ID,
		Nickname:        lookupResult.Nickname,
		MessageID:       messageID,
		ChannelID:       channelId,
		ParentMessageID: parentMsgId,
		Timestamp:       lookupResult.Timestamp,
		Lease:           lookupResult.Lease,
		Status:          channels.SentStatus(lookupResult.Status),
		Hidden:          lookupResult.Hidden,
		Pinned:          lookupResult.Pinned,
		Content:         lookupResult.Text,
		Type:            channels.MessageType(lookupResult.Type),
		Round:           id.Round(lookupResult.Round),
		PubKey:          lookupResult.Pubkey,
		CodesetVersion:  lookupResult.CodesetVersion,
	}, nil
}

// get is a generic private helper for getting values from the given
// [idb.ObjectStore].
func (w *wasmModel) get(objectStoreName string, key js.Value) (string, error) {
	parentErr := errors.Errorf("failed to get %s/%s", objectStoreName, key)

	// Prepare the Transaction
	txn, err := w.db.Transaction(idb.TransactionReadOnly, objectStoreName)
	if err != nil {
		return "", errors.WithMessagef(parentErr,
			"Unable to create Transaction: %+v", err)
	}
	store, err := txn.ObjectStore(objectStoreName)
	if err != nil {
		return "", errors.WithMessagef(parentErr,
			"Unable to get ObjectStore: %+v", err)
	}

	// Perform the operation
	getRequest, err := store.Get(key)
	if err != nil {
		return "", errors.WithMessagef(parentErr,
			"Unable to Get from ObjectStore: %+v", err)
	}

	// Wait for the operation to return
	ctx, cancel := newContext()
	resultObj, err := getRequest.Await(ctx)
	cancel()
	if err != nil {
		return "", errors.WithMessagef(parentErr,
			"Unable to get from ObjectStore: %+v", err)
	}

	// Process result into string
	resultStr := utils.JsToJson(resultObj)
	jww.DEBUG.Printf("Got from %s/%s: %s", objectStoreName, key, resultStr)
	return resultStr, nil
}

// getIndex is a generic private helper for getting values from the given
// [idb.ObjectStore] using a [idb.Index].
func (w *wasmModel) getIndex(objectStoreName string,
	indexName string, key js.Value) (js.Value, error) {

	parentErr := errors.Errorf("failed to getIndex %s/%s/%s",
		objectStoreName, indexName, key)

	// Prepare the Transaction
	txn, err := w.db.Transaction(idb.TransactionReadOnly, objectStoreName)
	if err != nil {
		return js.Null(), errors.WithMessagef(parentErr,
			"Unable to create Transaction: %+v", err)
	}
	store, err := txn.ObjectStore(objectStoreName)
	if err != nil {
		return js.Null(), errors.WithMessagef(parentErr,
			"Unable to get ObjectStore: %+v", err)
	}
	idx, err := store.Index(indexName)
	if err != nil {
		return js.Null(), errors.WithMessagef(parentErr,
			"Unable to get index: %+v", err)
	}

	// Perform the operation
	getRequest, err := idx.Get(key)
	if err != nil {
		return js.Null(), errors.WithMessagef(parentErr,
			"Unable to Get from ObjectStore: %+v", err)
	}

	// Wait for the operation to return
	ctx, cancel := newContext()
	resultObj, err := getRequest.Await(ctx)
	cancel()
	if err != nil {
		return js.Null(), errors.WithMessagef(parentErr,
			"Unable to get from ObjectStore: %+v", err)
	}

	jww.DEBUG.Printf("Got via index from %s/%s/%s",
		objectStoreName, indexName, key, resultObj)
	return resultObj, nil
}

func (w *wasmModel) msgIDLookup(messageID cryptoChannel.MessageID) (*Message,
	error) {
	msgIDStr := base64.StdEncoding.EncodeToString(messageID.Marshal())
	keyObj, err := w.getIndex(messageStoreName,
		messageStoreMessageIndex, js.ValueOf(msgIDStr))
	if err != nil {
		return nil, err
	} else if keyObj.IsUndefined() {
		return nil, errors.Errorf("no message for %s found", msgIDStr)
	}

	// Process result into string
	resultStr := utils.JsToJson(keyObj)
	jww.DEBUG.Printf("Index lookup of %s/%s/%s: %s",
		messageStoreName, messageStoreMessageIndex, msgIDStr, resultStr)

	resultMsg := &Message{}
	err = json.Unmarshal([]byte(resultStr), resultMsg)
	if err != nil {
		return nil, err
	}
	return resultMsg, nil
}

// dump returns the given [idb.ObjectStore] contents to string slice for
// debugging purposes.
func (w *wasmModel) dump(objectStoreName string) ([]string, error) {
	parentErr := errors.Errorf("failed to dump %s", objectStoreName)

	txn, err := w.db.Transaction(idb.TransactionReadOnly, objectStoreName)
	if err != nil {
		return nil, errors.WithMessagef(parentErr,
			"Unable to create Transaction: %+v", err)
	}
	store, err := txn.ObjectStore(objectStoreName)
	if err != nil {
		return nil, errors.WithMessagef(parentErr,
			"Unable to get ObjectStore: %+v", err)
	}
	cursorRequest, err := store.OpenCursor(idb.CursorNext)
	if err != nil {
		return nil, errors.WithMessagef(parentErr,
			"Unable to open Cursor: %+v", err)
	}

	// Run the query
	jww.DEBUG.Printf("%s values:", objectStoreName)
	results := make([]string, 0)
	ctx, cancel := newContext()
	err = cursorRequest.Iter(ctx,
		func(cursor *idb.CursorWithValue) error {
			value, err := cursor.Value()
			if err != nil {
				return err
			}
			valueStr := utils.JsToJson(value)
			results = append(results, valueStr)
			jww.DEBUG.Printf("- %v", valueStr)
			return nil
		})
	cancel()
	if err != nil {
		return nil, errors.WithMessagef(parentErr,
			"Unable to dump ObjectStore: %+v", err)
	}
	return results, nil
}
