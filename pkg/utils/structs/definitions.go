package structs

import (
	"encoding/json"
	"log"
	"time"
)

// Struct definition for main profile config
type Mainconfig struct {
	UUID       string   `json:"uuid"`
	KEYX       string   `json:"keyx"`
	AESPSK     string   `json:"aespsk"`
	BaseURL    string   `json:"baseurl"`
	BaseURLS   []string `json:"baseurls"`
	UserAgent  string   `json:"useragent"`
	Sleep      string   `json:"sleep"`
	HostHeader string   `json:"hostheader"`
}

// Struct definition for CheckIn messages
type CheckInMessage struct {
	Action         string `json:"action"`
	IP             string `json:"ip"`
	OS             string `json:"os"`
	User           string `json:"user"`
	Host           string `json:"host"`
	Pid            int    `json:"pid"`
	UUID           string `json:"uuid"`
	Architecture   string `json:"architecture"`
	Domain         string `json:"domain"`
	IntegrityLevel int    `json:"integrity_level"`
	ExternalIP     string `json:"external_ip"`
	EncryptionKey  string `json:"encryption_key"`
	DecryptionKey  string `json:"decryption_key"`
}

type CheckInMessageResponse struct {
	Action string `json:"action"`
	ID     string `json:"id"`
	Status string `json:"status"`
}

// Struct definitions for EKE-RSA messages

type EkeKeyExchangeMessage struct {
	Action    string `json:"action"`
	PubKey    string `json:"pub_key"`
	SessionID string `json:"session_id"`
}

type EkeKeyExchangeMessageResponse struct {
	Action     string `json:"action"`
	UUID       string `json:"uuid"`
	SessionKey string `json:"session_key"`
	SessionId  string `json:"session_id"`
}

// Struct definitions for Tasking request messages

type TaskRequestMessage struct {
	Action      string             `json:"action"`
	TaskingSize int                `json:"tasking_size"`
	Delegates   []*json.RawMessage `json:"delegates"`
}

type TaskRequestMessageResponse struct {
	Action    string             `json:"action"`
	Tasks     []Task             `json:"tasks"`
	Delegates []*json.RawMessage `json:"delegates"`
}

type Task struct {
	Command   string  `json:"command"`
	Params    string  `json:"parameters"`
	Timestamp float64 `json:"timestamp"`
	TaskID    string  `json:"id"`
	Job       *Job
}

type Job struct {
	KillChannel chan (int)
	Stop        *int
	Monitoring  bool
}

// Struct definitions for TaskResponse Messages
type TaskResponseMessage struct {
	Action    string            `json:"action"`
	Responses []json.RawMessage `json:"responses"`
	Delegates []json.RawMessage `json:"delegates"`
}

type Response struct {
	TaskID     string `json:"task_id"`
	UserOutput string `json:"user_output"`
	Completed  bool   `json:"completed"`
}

type TaskResponseMessageResponse struct {
	Action    string            `json:"action"`
	Responses []json.RawMessage `json:"responses"`
	Delegates []json.RawMessage `json:"delegates"`
}

type ServerResponse struct {
	TaskID string `json:"uuid"`
	Status string `json:"status"`
	Error  string `json:"error"`
}

type UserOutput struct {
	Output []byte `json:"user_output"`
}

// Struct definitions for file downloads and uploads
type FileDownloadInitialMessage struct {
	NumChunks int    `json:"total_chunks"`
	TaskID    string `json:"task_id"`
	FullPath  string `json:"full_path"`
}

type FileDownloadInitialMessageResponse struct {
	Status string `json:"status"`
	FileID string `json:"file_id"`
}

type FileDownloadChunkMessage struct {
	ChunkNum  int    `json:"chunk_num"`
	FileID    string `json:"file_id"`
	ChunkData string `json:"chunk_data"`
	TaskID    string `json:"task_id"`
}

type FileUploadChunkMessage struct {
	Action    string `json:"action"`
	ChunkSize int    `json:"chunk_size"`
	FileID    string `json:"file_id"`
	ChunkNum  int    `json:"chunk_num"`
	FullPath  string `json:"full_path"`
}

type FileUploadChunkMessageResponse struct {
	Action      string `json:"action"`
	TotalChunks int    `json:"total_chunks"`
	ChunkNum    int    `json:"chunk_num"`
	ChunkData   string `json:"chunk_data"`
}

//Message - struct definition for external C2 messages
type Message struct {
	Tag    string `json:"tag"`
	MType  int    `json:"mtype"`
	IDType int    `json:"idtype"`
	ID     string `json:"id"`
	Client bool   `json:"client"`
	Data   string `json:"data"`
}

//ThreadMsg used to send task results back to the receiving channel
type ThreadMsg struct {
	TaskItem   Task
	TaskResult []byte
	Error      bool
}

// TaskStub to post list of currently processing tasks.
type TaskStub struct {
	Command string `json:"command"`
	Params  string `json:"params"`
	ID      string `json:"id"`
}

// Job struct that will listen for messages on the kill channel,
// set the Stop param to an exit code, and checks if it's in a
// monitoring state.

//FileRegisterResponse used for holding the response after file registration
type FileRegisterResponse struct {
	Status string `json:"status"`
	FileID string `json:"file_id"`
}

// FileRegisterRequest used to register a file download
type FileRegisterRequest struct {
	Chunks int    `json:"total_chunks"`
	Task   string `json:"task"`
}

// NestedApfellTaskResponse used to hold the task response field
type NestedApfellTaskResponse struct {
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
	Command   string `json:"command"`
	Params    string `json:"params"`
	AttackID  int    `json:"attack_id"`
	Callback  int    `json:"callback"`
	Operator  string `json:"operator"`
}

// FileChunk used to send a file download chunk to apfell
type FileChunk struct {
	ChunkNumber int    `json:"chunk_num"`
	ChunkData   string `json:"chunk_data"`
	FileID      string `json:"file_id"`
}

// FileChunkResponse used to handle the FileChunk response from Apfell
type FileChunkResponse struct {
	Status string `json:"status"`
}

//FileUploadParams - handle parameters for the file upload response
type FileUploadParams struct {
	FileID     string `json:"file_id"`
	RemotePath string `json:"remote_path"`
}

// CheckInStruct used for Checkin messages to Apfell
type CheckInStruct struct {
	User           string `json:"user"`
	Host           string `json:"host"`
	Pid            int    `json:"pid"`
	IP             string `json:"ip"`
	UUID           string `json:"uuid"`
	IntegrityLevel int    `json:"integrity_level"`
}

// MonitorStop tells the job that it needs to wait for a kill signal.
// The individual module is required to listen for the job.Stop
// variable to be > 0, and take requisite actions to tear-down.
func (j *Job) MonitorStop() {
	if !j.Monitoring {
		j.Monitoring = true
		for {
			select {
			case <-j.KillChannel:
				log.Println("Got kill message for job")
				*j.Stop = 1
				j.Monitoring = false
				return
			default:
				// …
				// log.Println("Sleeping in the kill chan...")
				time.Sleep(time.Second)
			}
		}
	}
}

// SendKill sends a kill message to the channel.
func (j *Job) SendKill() {
	j.KillChannel <- 1
}

// ToStub converts a Task item to a TaskStub that's easily
// transportable between client and server.
func (t *Task) ToStub() TaskStub {
	return TaskStub{
		Command: t.Command,
		ID:      t.TaskID,
		Params:  t.Params,
	}
}
