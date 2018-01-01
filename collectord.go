package main

import (
    "fmt"
    "os"
    "os/exec"
    "strconv"
    "net"
    "strings"
    "flag"
    "log"
    "time"

    "github.com/BurntSushi/toml"
    "github.com/go-redis/redis"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "github.com/fln/nf9packet"
)




var (

    bytes_index int
    pkts_index int
    ip_src_index int
    device      string = "ens3"
    snapshotLen int32  = 1024
    promiscuous bool   = false
    err         error
    capturemode string
    filter      string
    ipaddr      string
    src_port    string
    dst_port    string
    pkts        int
    bytes       int
    total_pkts  int
    total_bytes int
    total_reqs  int
    influx      string
    timeout     time.Duration = 1 * time.Second
    handle      *pcap.Handle
)
// Info from config file
type Config struct {
        Influx string
        CaptureMode string
        Device   string
        CaptureFilter string
}
// Reads info from config file
func ReadConfig() Config {
        var configfile = "conf/collector.conf"
        _, err := os.Stat(configfile)
        if err != nil {
                log.Fatal("Config file is missing: ", configfile)
        }

        var config Config
        if _, err := toml.DecodeFile(configfile, &config); err != nil {
                log.Fatal(err)
        }
        //log.Print(config.Index)
        return config
}


func exec_shell(command string) string {
out, err := exec.Command("/bin/bash","-c",command).Output()
    if err != nil {
        log.Fatal(err)
    }
    return string(out)
}


func main() {

var config = ReadConfig()
capturemode = config.CaptureMode
device = config.Device
filter = config.CaptureFilter
influx = config.Influx

f, err := os.OpenFile("logs/collector.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
if err != nil {
        log.Fatal(err)
}
defer f.Close()
log.SetOutput(f)
log.Println("\nCaptureMode is "+capturemode+" \nDevice is "+device+" \nFilter is "+filter)
log.Println("Influx uri is "+influx)

if capturemode == "host-based" {
    // Open device
    log.Println("Host-based capture mode on")
    handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
    if err != nil {log.Fatal(err) }
    defer handle.Close()

    // Set filter
//  var filter string = "tcp and port 80 or port 443"
    err = handle.SetBPFFilter(filter)
    if err != nil {
        log.Fatal(err)
    }

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        printPacketInfo(packet)
    }
} else {
log.Println("Starting netflow collector")
nf_collector()
}


}

func printPacketInfo(packet gopacket.Packet) {
    ipLayer := packet.Layer(layers.LayerTypeIPv4)
    if ipLayer != nil {
//debug log.Println("IPv4 layer detected.")
        ip, _ := ipLayer.(*layers.IPv4)
 ///      log.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
        ipsrc := fmt.Sprintf("%s",ip.SrcIP)
        ipdst := fmt.Sprintf("%s",ip.DstIP)
        client := redis.NewClient(&redis.Options{
                Addr:     "localhost:6379",
                Password: "", // no password set
                DB:       0,  // use default DB
        })


        result_ip, err := client.Incr(ipsrc).Result()
        if err != nil {
            panic(err)
        }
        client.Close()

        tcpLayer := packet.Layer(layers.LayerTypeTCP)
    if tcpLayer != nil {
    //    log.Printf("TCP layer detected.\n")
        tcp, _ := tcpLayer.(*layers.TCP)
        fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
        src_port = fmt.Sprintf("%s",tcp.SrcPort)
        dst_port = fmt.Sprintf("%s",tcp.DstPort)
    }

    fmt.Println(result_ip)


        if influx != "" {
// DEBUG ONLY                           log.Println("curl -POST '"+influx+"' --data-binary 're8,ip-addr=\""+string(ipaddr)+"\" tot_reqs="+strconv.Itoa(total_reqs)+",tot_pkts="+strconv.Itoa(total_pkts)+",tot_bytes="+strconv.Itoa(total_bytes)+"'")
             log.Println("curl -POST '"+influx+"' --data-binary 're9,host=collectord ip-src=\""+string(ipsrc)+"\",ip-dst="+string(ipdst)+",src_port="+string(src_port)+",dst_port="+string(dst_port)+"'")
             exec_shell("curl -POST '"+influx+"' --data-binary 're9,host=collectord ip-src=\""+string(ipsrc)+"\",ip-dst=\""+string(ipdst)+"\",src_port=\""+string(src_port)+"\",dst_port=\""+string(dst_port)+"\"'")
                                                }

    if err := packet.ErrorLayer(); err != nil {
        log.Println("Error decoding some part of the packet:", err)
    }

}

}
// LAST_SWITCHED | FIRST_SWITCHED | IN_PKTS | IN_BYTES | INPUT_SNMP | OUTPUT_SNMP | IPV4_SRC_ADDR | IPV4_DST_ADDR | PROTOCOL | SRC_TOS | L4_SRC_PORT | L4_DST_PORT | IPV4_NEXT_HOP | DST_MASK | SRC_MASK | TCP_FLAGS | IN_DST_MAC | OUT_SRC_MAC | UNKNOWN_TYPE_225 | UNKNOWN_TYPE_226 | UNKNOWN_TYPE_227 | UNKNOWN_TYPE_228 |


// IPV4_SRC_ADDR | IPV4_DST_ADDR | IPV4_NEXT_HOP | L4_SRC_PORT | L4_DST_PORT | TCP_FLAGS | INPUT_SNMP | OUTPUT_SNMP | IN_PKTS | IN_BYTES | FIRST_SWITCHED | LAST_SWITCHED | PROTOCOL | SRC_TOS |
type templateCache map[string]*nf9packet.TemplateRecord

func NetflowToRedis(template *nf9packet.TemplateRecord, records []nf9packet.FlowDataRecord) {

        for i , f := range template.Fields {
                if strings.Contains(f.Name(),"PKTS") {  pkts_index = i }
                if f.Name() == "IN_BYTES" {  bytes_index = i }
                if f.Name() == "IPV4_SRC_ADDR" {  ip_src_index = i
                fmt.Println("\n Packets index is positioned at : "+strconv.Itoa(pkts_index)+" \n Bytes is positioned  at: "+strconv.Itoa(bytes_index)+" \n IPv4 source is positioned at : "+strconv.Itoa(ip_src_index))
}
           //     if i == 15 { os.Exit(3) }
        }



        for _, r := range records {
                for i := range r.Values {
                        colWidth := len(template.Fields[i].Name())
                        if (i == 1) {
                        fmt.Printf(" %"+strconv.Itoa(colWidth)+"s |", template.Fields[i].DataToString(r.Values[i]))
                        ipaddr =template.Fields[i].DataToString(r.Values[i])
                        client := redis.NewClient(&redis.Options{
                        Addr:     "localhost:6379",
                        Password: "", // no password set
                        DB:       0,  // use default DB
                        })
                        gui_client := redis.NewClient(&redis.Options{
                        Addr:     "localhost:6379",
                        Password: "", // no password set
                        DB:       1,// use default DB
                        })


                        val, err := client.Get(ipaddr+"_num_pkts").Result()
                        if err == redis.Nil {
                                log.Println("Pkt does not exist")
                        } else if err != nil {
                                panic(err)
                        } else {
                                fmt.Println("Found pkt value")
                        }
                        pkts_old, _ := strconv.Atoi(val)
                        pkts_current , _ := strconv.Atoi(template.Fields[pkts_index].DataToString(r.Values[pkts_index]))
                        pkts = pkts_old+ pkts_current
                        fmt.Println("Current Packets are ",pkts_current)
                        fmt.Println("Old Packets are ",pkts_old)
                        fmt.Println("Total Packets are ",pkts)
                        total_pkts = pkts_current + total_pkts
                        client.Set(ipaddr+"_num_pkts", pkts, 0).Err()
                        gui_client.Set("total_pkts", total_pkts,0).Err()


                        val2, err := client.Get(ipaddr+"_num_bytes").Result()
                        if err == redis.Nil {
                                log.Println("Bytes does not exist")
                        } else if err != nil {
                                panic(err)
                        } else {
                                fmt.Println("Found bytes value")
                        }
                        bytes_old, _ := strconv.Atoi(val2)
                        bytes_current , _ := strconv.Atoi(template.Fields[bytes_index].DataToString(r.Values[bytes_index]))
                        bytes = bytes_old+ bytes_current
                        total_bytes = bytes_current + bytes_old
                        fmt.Println("Current bytes are ",bytes_current)
                        fmt.Println("Old bytes are ",bytes_old)
                        fmt.Println("Total bytes are ",bytes)
                        client.Set(ipaddr+"_num_bytes", bytes, 0).Err()
                        gui_client.Set("total_bytes", total_bytes, 0).Err()



                        ipaddr = fmt.Sprintf("%s", template.Fields[ip_src_index].DataToString(r.Values[ip_src_index]))
                        client.Incr(ipaddr+"_num_reqs").Result()
                        val3, err := client.Get(ipaddr+"_num_reqs").Result()
                        if err == redis.Nil {
                                log.Println("Reqs does not exist")
                        } else if err != nil {
                                panic(err)
                        } else {
                                fmt.Println("Found reqs value")
                        }
                        total_reqs, _ = strconv.Atoi(val3)
                        gui_client.Set("total_reqs", total_reqs,0).Err()
                        if influx != "" {
// DEBUG ONLY                           log.Println("curl -POST '"+influx+"' --data-binary 're8,ip-addr=\""+string(ipaddr)+"\" tot_reqs="+strconv.Itoa(total_reqs)+",tot_pkts="+strconv.Itoa(total_pkts)+",tot_bytes="+strconv.Itoa(total_bytes)+"'")
                                exec_shell("curl -POST '"+influx+"' --data-binary 're8,ip-addr=\""+string(ipaddr)+"\" tot_reqs="+strconv.Itoa(total_reqs)+",tot_pkts="+strconv.Itoa(total_pkts)+",tot_bytes="+strconv.Itoa(total_bytes)+"'")
                                exec_shell("curl -POST '"+influx+"' --data-binary 'hosts-1,tag=collectord ip-addr=\""+string(ipaddr)+"\",tot_reqs="+strconv.Itoa(total_reqs)+",tot_pkts="+strconv.Itoa(total_pkts)+",tot_bytes="+strconv.Itoa(total_bytes)+"'")
                                                }
                        total_reqs = 0
                        total_bytes = 0
                        total_pkts = 0

                        client.Close()
                        gui_client.Close()
                        }
                }
                fmt.Printf("\n")
        }

}

func packetDump(addr string, data []byte, cache templateCache) {
        p, err := nf9packet.Decode(data)
        if err != nil {
                log.Println(err)
                return
        }

        log.Println("Starting record decoding")
        templateList := p.TemplateRecords()
        flowSets := p.DataFlowSets()
        for _, t := range templateList {
                templateKey := fmt.Sprintf("%s|%b|%v", addr, p.SourceId, t.TemplateId)
                cache[templateKey] = t
        }

        for _, set := range flowSets {
                templateKey := fmt.Sprintf("%s|%b|%v", addr, p.SourceId, set.Id)
                template, ok := cache[templateKey]
                if !ok {
                        // We do not have template for this Data FlowSet yet
                        continue
                }

                records := template.DecodeFlowSet(&set)
                if records == nil {
                        // Error in decoding Data FlowSet
                        continue
                }
                NetflowToRedis(template, records)
        }
}


func nf_collector() {
        listenAddr := flag.String("listen", ":9995", "Address to listen for NetFlow v9 packets.")
        flag.Parse()
        log.Println("Listening Netflow records on port 9995")
        addr, err := net.ResolveUDPAddr("udp", *listenAddr)
        if err != nil {
                panic(err)
        }

        con, err := net.ListenUDP("udp", addr)
        if err != nil {
                panic(err)
        }

        data := make([]byte, 8960)
        cache := make(templateCache)
        for {
                length, remote, err := con.ReadFrom(data)
                if err != nil {
                        panic(err)
                }

                packetDump(remote.String(), data[:length], cache)
        }

}
