package main

import (
  "fmt"
  "os/exec"
  "sync"
)


func start_speedtest(test_name string, cmd_map map[string]string, wg *sync.WaitGroup) {
  defer wg.Done()

  cmd_name := cmd_map[test_name]
  cmd := exec.Command(cmd_name)

  output, err := cmd.Output()
  if err != nil {
    fmt.Println(err)
  }

  fmt.Println(output)

}


