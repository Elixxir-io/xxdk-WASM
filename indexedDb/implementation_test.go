////////////////////////////////////////////////////////////////////////////////
// Copyright © 2022 xx foundation                                             //
//                                                                            //
// Use of this source code is governed by a license that can be found in the  //
// LICENSE file.                                                              //
////////////////////////////////////////////////////////////////////////////////

//go:build js && wasm

package indexedDb

import (
	"encoding/json"
	"fmt"
	"gitlab.com/xx_network/primitives/netTime"
	"os"
	"strconv"
	"testing"
	"time"

	jww "github.com/spf13/jwalterweatherman"
	"gitlab.com/elixxir/client/channels"
	"gitlab.com/elixxir/client/cmix/rounds"
	cryptoBroadcast "gitlab.com/elixxir/crypto/broadcast"
	"gitlab.com/elixxir/crypto/channel"
	"gitlab.com/xx_network/primitives/id"
)

func TestMain(m *testing.M) {
	jww.SetStdoutThreshold(jww.LevelDebug)
	os.Exit(m.Run())
}

func dummyCallback(uint64, *id.ID, bool) {}

// Test wasmModel.UpdateSentStatus happy path and ensure fields don't change.
func Test_wasmModel_UpdateSentStatus(t *testing.T) {
	testString := "test"
	testMsgId := channel.MakeMessageID([]byte(testString), &id.ID{1})
	eventModel, err := newWASMModel(testString, dummyCallback)
	if err != nil {
		t.Fatalf("%+v", err)
	}

	// Store a test message
	testMsg := buildMessage([]byte(testString), testMsgId.Bytes(), nil,
		testString, testString, []byte{8, 6, 7, 5}, 0, netTime.Now(),
		time.Second, 0, 0, channels.Sent)
	uuid, err := eventModel.receiveHelper(testMsg)
	if err != nil {
		t.Fatalf("%+v", err)
	}

	// Ensure one message is stored
	results, err := eventModel.dump(messageStoreName)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Expected 1 message to exist")
	}

	// Update the sentStatus
	expectedStatus := channels.Failed
	eventModel.UpdateSentStatus(uuid, testMsgId, netTime.Now(),
		rounds.Round{ID: 8675309}, expectedStatus)

	// Check the resulting status
	results, err = eventModel.dump(messageStoreName)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Expected 1 message to exist")
	}
	resultMsg := &Message{}
	err = json.Unmarshal([]byte(results[0]), resultMsg)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	if resultMsg.Status != uint8(expectedStatus) {
		t.Fatalf("Unexpected Status: %v", resultMsg.Status)
	}

	// Make sure other fields didn't change
	if resultMsg.Nickname != testString {
		t.Fatalf("Unexpected Nickname: %v", resultMsg.Nickname)
	}
}

// Smoke test wasmModel.JoinChannel/wasmModel.LeaveChannel happy paths.
func Test_wasmModel_JoinChannel_LeaveChannel(t *testing.T) {
	eventModel, err := newWASMModel("test", dummyCallback)
	if err != nil {
		t.Fatalf("%+v", err)
	}

	testChannel := &cryptoBroadcast.Channel{
		ReceptionID: id.NewIdFromString("test", id.Generic, t),
		Name:        "test",
		Description: "test",
		Salt:        nil,
	}
	testChannel2 := &cryptoBroadcast.Channel{
		ReceptionID: id.NewIdFromString("test2", id.Generic, t),
		Name:        "test2",
		Description: "test2",
		Salt:        nil,
	}
	eventModel.JoinChannel(testChannel)
	eventModel.JoinChannel(testChannel2)
	results, err := eventModel.dump(channelsStoreName)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	if len(results) != 2 {
		t.Fatalf("Expected 2 channels to exist")
	}
	eventModel.LeaveChannel(testChannel.ReceptionID)
	results, err = eventModel.dump(channelsStoreName)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Expected 1 channels to exist")
	}
}

// Test UUID gets returned when different messages are added.
func Test_wasmModel_UUIDTest(t *testing.T) {
	testString := "testHello"
	eventModel, err := newWASMModel(testString, dummyCallback)
	if err != nil {
		t.Fatalf("%+v", err)
	}

	uuids := make([]uint64, 10)

	for i := 0; i < 10; i++ {
		// Store a test message
		channelID := id.NewIdFromBytes([]byte(testString), t)
		msgID := channel.MessageID{}
		copy(msgID[:], testString+fmt.Sprintf("%d", i))
		rnd := rounds.Round{ID: id.Round(42)}
		uuid := eventModel.ReceiveMessage(channelID, msgID, "test",
			testString+fmt.Sprintf("%d", i), []byte{8, 6, 7, 5}, 0,
			netTime.Now(), time.Hour, rnd, 0, channels.Sent)
		uuids[i] = uuid
	}

	_, _ = eventModel.dump(messageStoreName)

	for i := 0; i < 10; i++ {
		for j := i + 1; j < 10; j++ {
			if uuids[i] == uuids[j] {
				t.Fatalf("uuid failed: %d[%d] == %d[%d]",
					uuids[i], i, uuids[j], j)
			}
		}
	}
}

// Tests if the same message ID being sent always returns the same UUID.
func Test_wasmModel_DuplicateReceives(t *testing.T) {
	testString := "testHello"
	eventModel, err := newWASMModel(testString, dummyCallback)
	if err != nil {
		t.Fatalf("%+v", err)
	}

	uuids := make([]uint64, 10)

	msgID := channel.MessageID{}
	copy(msgID[:], testString)
	for i := 0; i < 10; i++ {
		// Store a test message
		channelID := id.NewIdFromBytes([]byte(testString), t)
		rnd := rounds.Round{ID: id.Round(42)}
		uuid := eventModel.ReceiveMessage(channelID, msgID, "test",
			testString+fmt.Sprintf("%d", i), []byte{8, 6, 7, 5}, 0,
			netTime.Now(), time.Hour, rnd, 0, channels.Sent)
		uuids[i] = uuid
	}

	_, _ = eventModel.dump(messageStoreName)

	for i := 0; i < 10; i++ {
		for j := i + 1; j < 10; j++ {
			if uuids[i] != uuids[j] {
				t.Fatalf("uuid failed: %d[%d] != %d[%d]",
					uuids[i], i, uuids[j], j)
			}
		}
	}
}

// Happy path: Inserts many messages, deletes some, and checks that the final
// result is as expected.
func Test_wasmModel_deleteMsgByChannel(t *testing.T) {
	testString := "test_deleteMsgByChannel"
	totalMessages := 10
	expectedMessages := 5
	eventModel, err := newWASMModel(testString, dummyCallback)
	if err != nil {
		t.Fatalf("%+v", err)
	}

	// Create a test channel id
	deleteChannel := id.NewIdFromString("deleteMe", id.Generic, t)
	keepChannel := id.NewIdFromString("dontDeleteMe", id.Generic, t)

	// Store some test messages
	for i := 0; i < totalMessages; i++ {
		testStr := testString + strconv.Itoa(i)

		// Interleave the channel id to ensure cursor is behaving intelligently
		thisChannel := deleteChannel
		if i%2 == 0 {
			thisChannel = keepChannel
		}

		testMsgId := channel.MakeMessageID([]byte(testStr), &id.ID{1})
		eventModel.ReceiveMessage(thisChannel, testMsgId, testStr, testStr,
			[]byte{8, 6, 7, 5}, 0, netTime.Now(), time.Second,
			rounds.Round{ID: id.Round(0)}, 0, channels.Sent)
	}

	// Check pre-results
	result, err := eventModel.dump(messageStoreName)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	if len(result) != totalMessages {
		t.Errorf("Expected %d messages, got %d", totalMessages, len(result))
	}

	// Do delete
	err = eventModel.deleteMsgByChannel(deleteChannel)
	if err != nil {
		t.Error(err)
	}

	// Check final results
	result, err = eventModel.dump(messageStoreName)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	if len(result) != expectedMessages {
		t.Errorf("Expected %d messages, got %d", expectedMessages, len(result))
	}
}
