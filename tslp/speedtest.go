package main

import (
  "fmt"
  "os/exec"
  //"sync"
  //"time"
)


func start_speedtest(test_name string, cmd_map map[string][]string, done chan<- bool) {
  cmd_name := cmd_map[test_name]
  fmt.Println(cmd_name)
  //time.Sleep(2 * time.Second)
  cmd := exec.Command(cmd_name[0], cmd_name[1:]...)

  output, err := cmd.Output()
  if err != nil {
    fmt.Println(err)
  }

  fmt.Println(string(output))
  done <- true
}


