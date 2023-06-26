package utils

import (
  "fmt"
  "net"
  "github.com/google/gopacket"
  "github.com/google/gopacket/layers"
  "sync"
  "os"
  "time"
  "github.com/google/gopacket/pcapgo"
  "github.com/google/gopacket/pcap"
)


func GetLocalIP(ver string) string {
  var ip string
  if ver == "v4" {
    ip = "8.8.8.8:80"
  } else {
    ip = "[2001:4860:4860::8888]:80"
  }
  conn, err := net.Dial("udp", ip)
  if err != nil {
      fmt.Println("error finding IP", ver)
      return "::1"
  }
  defer conn.Close()

  localAddr := conn.LocalAddr().(*net.UDPAddr)
  return localAddr.IP.String()
}


func GetDefaultInterface() (net.Interface, error) {
  interfaces, err := net.Interfaces()
  if err != nil {
    return net.Interface{}, err
  }

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return net.Interface{}, err
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.IsLoopback() {
        break
      } else {
        return iface, nil
			}
		}
	}
	return net.Interface{}, fmt.Errorf("default interface not found")
}


func IsIPv6Packet(packet gopacket.Packet) bool {
	if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		// IPv6 packet
		return true
	}
	return false
}


func GetKeyWithMaxValue(m map[string]int) string {
	maxKey := ""
	maxValue := 0
	for key, value := range m {
		if value > maxValue {
			maxKey = key
			maxValue = value
		}
	}
	return maxKey
}


func IsIPv4String(address string) bool {
	ip := net.ParseIP(address)
	return ip != nil && ip.To4() != nil
}



func StartCaptureWithContext(wg *sync.WaitGroup, addr string, resultChan chan<- error) {
  fmt.Println("starting capture")
	// Open the default network interface for packet capture
  snaplen := int32(96)
  iface, err  := GetDefaultInterface()
  if err != nil {
  	resultChan <- err
  }

    handle, err := pcap.OpenLive(iface.Name, snaplen, true, pcap.BlockForever)
	if err != nil {
		resultChan <- fmt.Errorf("failed to open device: %w", err)
		return 
	}
	defer handle.Close()

	// Set a filter for capturing specific packets (optional)
  filter := fmt.Sprintf("tcp and host %s", addr)
  if err := handle.SetBPFFilter(filter); err != nil {
		resultChan <- fmt.Errorf("failed to set BPF filter: %w", err)
		return 
	}

  fileName := fmt.Sprintf("capture-%s.pcap", time.Now().Format("20060102-150405"))
  pcapFile, err := os.Create(fileName)
  if err != nil {
		resultChan <- fmt.Errorf("failed to create PCAP file: %w", err)
		return
	}
  defer pcapFile.Close()

  pcapWriter := pcapgo.NewWriter(pcapFile)

	// Write PCAP file header
	if err := pcapWriter.WriteFileHeader(96, handle.LinkType()); err != nil {
		resultChan <- fmt.Errorf("failed to write PCAP file header: %w", err)
		return 
	}

	// Start capturing packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Write the packet to the PCAP file
		if err := pcapWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
			resultChan <- fmt.Errorf("failed to write packet to PCAP file: %w", err)
			return 
		}
	}
	fmt.Println("Waiting for speedtest to end")	
  	wg.Done()
  
  resultChan <- nil 
}
