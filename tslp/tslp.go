package main


import (
  "fmt"
  "log"
  "net"
  "sync"
  "github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
  "github.com/google/gopacket/layers"
  "time"
  "tslp/tslp/utils"
  "tslp/tslp/probing"
  //"golang.org/x/net/ipv6"
  //"golang.org/x/net/ipv4"
)



func find_server(test_name string, filter_map map[string]string) string {
  localIPv4 := utils.GetLocalIP("v4")
  localIPv6 := utils.GetLocalIP("v6")
  //packet capture params
  var snaplen int32 = 96
  num_pkts := 0
  iface, err := utils.GetDefaultInterface()
  if err != nil {
    fmt.Println("Failed to get default interface:", err)
    return ""
  }

  capture_filter := filter_map[test_name]
  handle, err := pcap.OpenLive(iface.Name, snaplen, false, pcap.BlockForever)
  if err != nil {
    log.Fatal(err)
  }

  defer handle.Close()

  // Set the capture filter
  err = handle.SetBPFFilter(capture_filter)
  if err != nil {
    log.Fatal(err)
  }

  ipCountMap := make(map[string]int)
  var localIP string
  // Start capturing packets
  packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
  var sourceIP string
  var destIP string
  var serverIP string
  for packet := range packetSource.Packets() {

    if utils.IsIPv6Packet(packet) {
      ipPacket, _ := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
      sourceIP = ipPacket.SrcIP.String()
      destIP = ipPacket.DstIP.String()
      localIP = localIPv6
    } else {
       ipPacket, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
       sourceIP = ipPacket.SrcIP.String()
       destIP = ipPacket.DstIP.String()
       localIP = localIPv4
    }
    //fmt.Println(localIP, srcIP, destIP)
    if sourceIP == localIP {
      serverIP = destIP
    } else {
      serverIP = sourceIP
    }

    if _, ok := ipCountMap[serverIP]; !ok {
      ipCountMap[serverIP] = 0
    }
    ipCountMap[serverIP] += 1
    // Process captured packet
    num_pkts += 1
    if num_pkts == 1000 {
      break
    }
  }
  serverIPMax := utils.GetKeyWithMaxValue(ipCountMap)
  return serverIPMax
}

/*
func pingWithTTLv6(destination string, ttl int) (time.Duration, error) {
	var conn net.Conn
	var err error

	conn, err = net.Dial("ipv6:icmp", destination)
	if err != nil {
    fmt.Println("error in setting conn", err)
		return 0, err
	}
	defer conn.Close()

	start := time.Now()
	_, err = conn.Write([]byte("ping"))
	if err != nil {
		return 0, err
	}

	buffer := make([]byte, 1024)
	err = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err != nil {
    fmt.Println("Error in reading", err)
		return 0, err
	}

	_, err = conn.Read(buffer)
	if err != nil {
		return 0, err
	}

	elapsed := time.Since(start)
	return elapsed, nil
}
*/



func pingWithTTLv4(destination string, ttl int) (time.Duration, error) {
	var conn net.Conn
	var err error

	conn, err = net.Dial("ip4:icmp", destination)
	if err != nil {
    fmt.Println("error in setting conn", err)
		return 0, err
	}
	defer conn.Close()

	start := time.Now()
	_, err = conn.Write([]byte("ping"))
	if err != nil {
		return 0, err
	}

	buffer := make([]byte, 1024)
	err = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if err != nil {
    fmt.Println("Error in reading", err)
		return 0, err
	}

	_, err = conn.Read(buffer)
	if err != nil {
		return 0, err
	}

	elapsed := time.Since(start)
	return elapsed, nil
}

func tslp(serverIP string, numHops int) {
  for i := 1; i <= numHops+1; i++ {
    fmt.Println("starting ping", i)
  }
}


func main() {
  
  resultChan := make(chan error)

  var speedtest_sync sync.WaitGroup
  speedtest_sync.Add(1)

  var cmd_map = map[string]string{
    "mlab": "ndt7-client",
    "ookla": "speedtest",
  }

  var filter_map = map[string]string {
    "mlab": "port 443",
    "ookla": "port 8080 or port 5060",
  }

  var test_name = "mlab"

  go start_speedtest(test_name, cmd_map, &speedtest_sync)
  serverIP := find_server(test_name, filter_map)
  go utils.StartCaptureWithContext(&speedtest_sync, serverIP, resultChan)
  //addr := "www.google.com"
  pinger, err := probing.NewPinger(serverIP)
  if err != nil {
    panic(err)
  }
  pinger.SetPrivileged(false)
  pinger.Interval = 500*time.Millisecond
  pinger.Count = 3
  pinger.TTL = 2
  err = pinger.Run() // Blocks until finished.
  if err != nil {
    panic(err)
  }
  stats := pinger.Statistics() // get send/receive/duplicate/rtt stats
  fmt.Println(stats)
  
  /*
  serverIP := "www.google.com"
  numHops := 2
  tslp(serverIP, numHops)
  */
  speedtest_sync.Wait()
  result := <-resultChan
  if result != nil {
    fmt.Println(result)
  }
}
