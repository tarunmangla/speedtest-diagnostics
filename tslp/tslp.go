package main


import (
  "fmt"
  "log"
  //"sync"
  "github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
  "github.com/google/gopacket/layers"
  "time"
  "tslp/tslp/utils"
  "tslp/tslp/probing"
  "context"
  "sort"
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
  fmt.Println("Interface is ", iface.Name)
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



func printPackets(p *probing.Pinger) {
  for id := range(p.SentTimestamps) {
    timestamp := p.SentTimestamps[id]
    rtt := p.RttMap[id]
    fmt.Println(timestamp, rtt)
  }
}

func getTimeBoundaries(captureFile string) (int64, int64) {
  fmt.Println(captureFile)
  // Open the pcap file for reading
  handle, err := pcap.OpenOffline(captureFile)
  if err != nil {
    log.Fatal(err)
  }
  defer handle.Close()

  // Get Local IP
  localIPv4 :=  utils.GetLocalIP("v4")
  localIPv6 := utils.GetLocalIP("v6")
  timebin := int64(100) // Time bin in milliseconds  
  downVolTimebinMap := make(map[int64]int)
  upVolTimebinMap := make(map[int64]int)
  // Start processing packets
  packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

  for packet := range packetSource.Packets() {
    // Get the packet timestamp

    packetTime := packet.Metadata().Timestamp.UnixNano() / int64(time.Millisecond)
    packetTimebin := int64(packetTime/timebin)*timebin
    
    networkLayer := packet.NetworkLayer()
    if networkLayer == nil {
      // Skip non-IP packets
      continue
    }

    // Extract the source and destination IP addresses
    var srcIP, localIP string
    var size int
    switch ipLayer := networkLayer.(type) {
    case *layers.IPv4:
      srcIP = ipLayer.SrcIP.String()
      localIP = localIPv4
      size = int(ipLayer.Length)
    case *layers.IPv6:
      srcIP = ipLayer.SrcIP.String()
      localIP = localIPv6
      size = int(ipLayer.Length)
    }

    if _, ok := downVolTimebinMap[packetTimebin]; !ok {
      downVolTimebinMap[packetTimebin] = 0
      upVolTimebinMap[packetTimebin] = 0
    }

    if srcIP == localIP {
        upVolTimebinMap[packetTimebin] += size
    } else {
        downVolTimebinMap[packetTimebin] += size
    }
  }

  dataDirTimeMap := make(map[int64]int)
  var downloadEndTime, uploadEndTime int64
  
  MIN_VOL := 1000
  for timebin := range(downVolTimebinMap) {
    downVol := downVolTimebinMap[timebin]
    upVol := upVolTimebinMap[timebin]
    maxVol := downVol
    if downVol < upVol {
      maxVol = upVol
    }
    if maxVol < MIN_VOL {
      continue
    }
  
    if upVol > downVol {
      dataDirTimeMap[timebin] = 0 // upload
    } else {
      dataDirTimeMap[timebin] = 1
    }
  }

  keys := make([]int64, 0, len(dataDirTimeMap))
  
  for key := range dataDirTimeMap {
    keys = append(keys, key)
  }
  sort.Slice(keys, func(i, j int) bool {
    return keys[i] < keys[j]
  })
  //minTimebin := keys[0]
  for _, timebin := range(keys) {
    //diff := (timebin - minTimebin) / 1000
    //fmt.Println(diff, downVolTimebinMap[timebin], upVolTimebinMap[timebin])
    if dataDirTimeMap[timebin] == 0 {
      uploadEndTime = timebin
    } else {
      downloadEndTime = timebin
    }
  }
  
  return downloadEndTime, uploadEndTime
}

func within_range(ts int64, stTime int64, enTime int64) bool {
  if stTime > 0 && ts < stTime {
    return false
  }
  if enTime > 0 && ts > enTime {
    return false
  }
  return true
}


func GetStats(timestamps map[uint16]time.Time, rtts map[uint16]time.Duration, stTime int64, enTime int64, ttl int) {
  var rttList []int 
  for seq := range(timestamps) {
    timestamp := timestamps[seq].UnixNano() / int64(time.Millisecond)
    rtt := int(rtts[seq].Milliseconds())
    if within_range(timestamp, stTime, enTime) {
      rttList = append(rttList, rtt)
    }
  }
  sort.Ints(rttList)
  percentiles := []int{10, 25, 50, 75, 90}
  fmt.Println("Percentile value for TTL: ", ttl)
  for _, percentile := range(percentiles) {
    index := int(float64(percentile) / 100 * float64(len(rttList)-1))
    val := rttList[index]
    fmt.Println(percentile, val)
  }
}

func ProcessLatency(p *probing.Pinger, downloadEndTime int64, uploadEndTime int64) {
  diff := uploadEndTime - downloadEndTime 
  fmt.Println(downloadEndTime, uploadEndTime, diff)
  fmt.Println(p.Ipaddr)
  GetStats(p.SentTimestamps, p.RttMap, -1, downloadEndTime, p.TTL)
  GetStats(p.SentTimestamps, p.RttMap, downloadEndTime, uploadEndTime, p.TTL)
  GetStats(p.SentTimestamps, p.RttMap, uploadEndTime, -1, p.TTL)
}



func main() {
  
  result_chan := make(chan string)
  speedtest_done := make(chan bool, 1)
  
  var cmd_map = make(map[string][]string)

  // Assumes that these binaries are installed 
  cmd_map["mlab"] = []string{"ndt7-client", "-format=json", "-quiet"}
  cmd_map["ookla"] = []string{"speedtest", "--format=json"}
  
  ping_ctx, cancel := context.WithCancel(context.Background())

  var filter_map = map[string]string {
    "mlab": "port 443",
    "ookla": "port 8080 or port 5060",
  }

  var test_name = "mlab"

  go start_speedtest(test_name, cmd_map, speedtest_done)
  serverIP := find_server(test_name, filter_map)
  go utils.StartCaptureWithContext(serverIP, result_chan, speedtest_done)
  //addr := "www.google.com"
  max_ttl := 12
  pingerList := make([]*probing.Pinger, max_ttl)
  for i:= 0; i < max_ttl; i++ {
    pinger, err := probing.NewPinger(serverIP)
    if err != nil {
      panic(err)
    }
    pinger.SetPrivileged(true)
    pinger.Interval = 50*time.Millisecond
    //pinger.Count = 10
    // Modify the probing code to log IP address of each ICMP timeout
    // Confirm if it is sending UDP packets
    pinger.TTL = i+1
    pingerList[i] = pinger  
    go pinger.RunWithContext(ping_ctx) // Blocks until finished.
  }
  
  
  result := <-result_chan
  if result == "" {    
    fmt.Println("Error creating pcap traffic")
  }
  fmt.Println("Speed test finished")
  time.Sleep(10 * time.Second)
  //cancel ping
  fmt.Println("canceling ping")
  cancel()
 
  // Fix this code for ookla 
  downloadEndTime, uploadEndTime := getTimeBoundaries(result)
  
  // Change this to dump the data 
  for i:= 0; i < max_ttl; i++ {
    ProcessLatency(pingerList[i], downloadEndTime, uploadEndTime)
  }
}
