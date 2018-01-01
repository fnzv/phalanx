package main

import (
        "os/exec"
        "os"
        "fmt"
        "log"
)




func exec_shell(command string) string {
out, err := exec.Command("/bin/bash","-c",command).Output()
    if err != nil {
        log.Fatal(err)
    }
    return string(out)
}

func main() {

if len(os.Args) > 1 {
        action := os.Args[1]

        if action == "start" {
        exec_shell("screen -S COLLECTORD -d -m ./collectord")
        exec_shell("screen -S DETECTORD -d -m ./detectord")
        fmt.Println("Started all services")
                                }
        if action == "stop" { exec_shell("killall detectord && killall collectord") }
} else {
fmt.Println("Usage example:\n ./service (start|stop) ")
}


}
