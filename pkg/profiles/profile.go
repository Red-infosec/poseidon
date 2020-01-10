package profiles

import (
	"crypto/rsa"
	"encoding/base64"
	"math/rand"
	"time"

	"github.com/xorrior/poseidon/pkg/utils/crypto"

	"github.com/xorrior/poseidon/pkg/utils/structs"
)

// PConfig - Persistent C2 config values
var PConfig = structs.Mainconfig{
	"UUI",                                    // Unique identifier from Apfell
	"T",                                      // Key exchange boolean
	"AESPSK",                                 // AES Pre-shared key from Apfell
	"http(s)://callback_host:callback_port/", // Callback url
	[]string{},                               // Call back urls
	"Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en) AppleWebKit/419.3 (KHTML, like Gecko) Safari/419.3", // User Agent
	"10", // Sleep interval. Converted to an integer in the profile,
	"",   // Host Header
}

var (
	seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
	ApiVersion            = "1.4"
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
	CheckIn(ip string, pid int, user string, host string) interface{} // CheckIn method for sending the initial checkin to the server
	GetTasking() interface{}                                          // GetTasking method for retrieving the next task from apfell
	PostResponse(task structs.Task, output string) []byte             // Post a task response to the server
	NegotiateKey() string                                             // Start EKE key negotiation for encrypted comms
	SendFile(task structs.Task, params string)                        // C2 profile implementation for downloading files
	GetFile(fileDetails structs.FileUploadParams) bool                // C2 Profile implementation to get a file with specified id // C2 profile helper function to retrieve any arbitrary value for a profile
	SendFileChunks(task structs.Task, data []byte)                    // C2 helper function to upload a file
	Header() string
	SetHeader(hostname string)
	URL() string
	SetURL(url string)
	SetURLs(urls []string)
	SleepInterval() int
	SetSleepInterval(interval int)
	XKeys() bool
	SetXKeys(exchangingkeys bool)
	SetUserAgent(ua string)
	GetUserAgent() string
	ApfID() string
	SetApfellID(newID string)
	UniqueID() string
	SetUniqueID(newUUID string)
	AesPreSharedKey() string
	SetAesPreSharedKey(newkey string)
	RsaKey() *rsa.PrivateKey
	SetRsaKey(newKey *rsa.PrivateKey)
}

func NewInstance() interface{} {
	return newProfile()
}

func EncryptMessage(msg []byte, k string) []byte {
	key, _ := base64.StdEncoding.DecodeString(k)
	return crypto.AesEncrypt(key, msg)
}

func DecryptMessage(msg []byte, k string) []byte {
	key, _ := base64.StdEncoding.DecodeString(k)
	decMsg, _ := base64.StdEncoding.DecodeString(string(msg))
	return crypto.AesDecrypt(key, decMsg)
}

func GenerateSessionID() string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 20)
	for i := range b {
		b[i] = letterBytes[seededRand.Intn(len(letterBytes))]
	}
	return string(b)
}
