package main

import (
    "strings"
    "os/exec"
    "time"
    "strconv"
    "os"
    "fmt"
    "log"

    "github.com/BurntSushi/toml"
    "github.com/go-redis/redis"
)

var max_req int
var max_pkts int
var max_bytes int
var time_duration int64
var whitelist []string
var bantime string
var bannedips string
var dryrun string
var capturemode string
var banmode string

// Info from config file
type Config struct {
        MaxReq   int
        MaxPkts   int
        MaxBytes   int
        TimeDuration    int64
        BanTime  string
        Whitelist       []string
        DryRun  string
        CaptureMode string
        BanMode string
}

// Reads info from config file
func ReadConfig() Config {
        var configfile = "conf/detector.conf"
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

max_req = config.MaxReq
max_pkts = config.MaxPkts
max_bytes = config.MaxBytes
time_duration = config.TimeDuration
whitelist = config.Whitelist
bantime = config.BanTime
dryrun = config.DryRun
capturemode = config.CaptureMode
banmode = config.BanMode

f, err := os.OpenFile("logs/detector.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
if err != nil {
        log.Fatal(err)
}
defer f.Close()
log.SetOutput(f)


log.Println("Starting detectord with mode: "+capturemode+" and banmode: "+banmode)
log.Println("Thresholds - Max Req "+strconv.Itoa(max_req)+" - Max Pkts "+strconv.Itoa(max_pkts)+" - Max Bytes "+strconv.Itoa(max_bytes))
log.Println("Time duration is "+strconv.FormatInt(time_duration,10))
log.Println("Ban time: "+bantime)
log.Println("Dry run: "+dryrun)

i1 := 0

if capturemode == "host-based" {

for range whitelist {
    log.Println("Adding to whitelist: "+whitelist[i1])
    bannedips = bannedips + whitelist[i1]
    //fmt.Printf("%s", out)
     if dryrun == "false" {
     exec_shell("iptables -I INPUT -s "+whitelist[i1]+" -j ACCEPT -m comment --comment 'WHITELISTED IP - DETECTORD'")
        }
    i1++
}

if dryrun == "false" {
  if banmode == "ipset" {
    exec_shell("/sbin/iptables-save | awk '!x[$0]++'  |grep -v current_bans | /sbin/iptables-restore")
    check_ipset := exec_shell("ipset list | grep current | awk '{print $2}'")
    if strings.Contains(check_ipset,"bans") {
    log.Println("ipset already existing")
    } else {
    log.Println("creating ipset")
    exec_shell("ipset create current_bans hash:ip timeout 0")
    }
    exec_shell("iptables -A INPUT -m set --match-set current_bans src -j DROP")
        }

}

    for t := range time.NewTicker(time.Duration(time_duration) * time.Second).C {
        detector(t)
    }
} else {

  if banmode == "ipset" {
    exec_shell("/sbin/iptables-save | awk '!x[$0]++'  |grep -v current_bans | /sbin/iptables-restore")
    check_ipset := exec_shell("ipset list | grep current | awk '{print $2}'")
    if strings.Contains(check_ipset,"bans") {
    log.Println("ipset already existing")
    } else {
    log.Println("creating ipset")
    exec_shell("ipset create current_bans hash:ip timeout 0")
    }
    exec_shell("iptables -A INPUT -m set --match-set current_bans src -j DROP")
        }


log.Println("Reading from redis netflow data")
for t := range time.NewTicker(time.Duration(time_duration) * time.Second).C {
        detector_nf(t)
    }
}


}










func detector(tick time.Time) {

//  fmt.Println("Tick at: ", tick)

        client := redis.NewClient(&redis.Options{
                Addr:     "localhost:6379",
                Password: "", // no password set
                DB:       0,  // use default DB
        })



var keys []string
var cursor uint64
var n int
//var time_duration int
for {
    var err error
    keys, cursor, err = client.Scan(cursor, "", 100).Result()
    if err != nil {
        panic(err)
    }
    n += len(keys)
    if cursor == 0 {
        break
    }

}



for _, key := range keys {
        ipaddr := string(key)
        raw_reqs, _ := client.Get(key).Result()
        num_reqs, _ := strconv.Atoi(raw_reqs)
        if num_reqs > max_req {
                log.Println("BAN TRIGGERED because above max_req: ",max_req)
                log.Println("Recorded requests: ", num_reqs)
                log.Println("Configuring blocking rule for "+ipaddr+"\n")
                bannedips = bannedips + exec_shell("ipset list")
  if strings.Contains(bannedips,ipaddr) {
        log.Println("IP Already banned")
  } else {
        //ban_client.Incr(ipaddr+"_banned").Result()
        if dryrun == "false" {

                if banmode == "ipset" {
                                fmt.Println("ipset add current_bans "+ipaddr+" timeout "+bantime)
                                        exec_shell("ipset add current_bans "+ipaddr+" timeout "+bantime)
                                        log.Println("Adding "+ipaddr+" to ipset for "+bantime)
                                        }
                if banmode == "trigger" {
                                                exec_shell(" trigger.sh "+ipaddr+" "+bantime+" &")
                                                log.Println("Custom Trigger script launched!!")
                                }

        }
        }
client.FlushAll()

                        }
                     }
}









func detector_nf(tick time.Time) {

//  fmt.Println("Tick at: ", tick)




var keys []string
var cursor uint64
var n int
//var time_duration int
        client := redis.NewClient(&redis.Options{
                Addr:     "localhost:6379",
                Password: "", // no password set
                DB:       0,  // use default DB
        })
        ban_client := redis.NewClient(&redis.Options{
                Addr:     "localhost:6379",
                Password: "", // no password set
                DB:       2,  // use default DB
        })
for {
    var err error
    keys, cursor, err = client.Scan(cursor, "*_num_*", 100).Result()
    if err != nil {
        panic(err)
    }
    n += len(keys)
    if cursor == 0 {
        break
    }

}
bannedips = bannedips+ "0.0.0.0"

int_bantime,_ :=strconv.Atoi(bantime)

for _, key := range keys {

        if strings.Contains(string(key),"num_reqs") {
        ipaddr := strings.Replace(string(key), "_num_reqs", "", 1)
       // fmt.Println("Found Value: "+ipaddr)
        raw_reqs, _ := client.Get(key).Result()
        num_reqs, _ := strconv.Atoi(raw_reqs)
        if num_reqs > max_req {
                log.Println("BAN TRIGGERED because above max_req: ",max_req)
                log.Println("Recorded requests: ", num_reqs)
                log.Println("Configuring blocking rule for "+ipaddr+"\n")
                bannedips = bannedips+ exec_shell("ipset list")
          if strings.Contains(bannedips,ipaddr) {
                log.Println("IP Already banned")
          } else {
//       ban_client := redis.NewClient(&redis.Options{ Addr:     "localhost:6379",Password: "",DB: 3,    })
                 if dryrun == "false" {
                        if banmode == "ipset" {
                                                log.Println("Adding "+ipaddr+" to ipset for "+bantime)
                                                log.Println("ipset add current_bans "+ipaddr+" timeout "+bantime)
                                                exec_shell("ipset add current_bans "+ipaddr+" timeout "+bantime)
//                                              ban_client.Incr(ipaddr+"_banned").Result()
                                                ban_client.Set(ipaddr+"_banned",bantime,time.Duration(int_bantime)*time.Second).Err()
                        }
                        if banmode == "trigger" {
                                                exec_shell(" trigger.sh "+ipaddr+" "+bantime+" &")
                                                log.Println("Custom Trigger script launched!!")
                                                ban_client.Set(ipaddr+"_banned",bantime,time.Duration(int_bantime)*time.Second).Err()
                                }
                                      }
                }
                        client.FlushDb()
                        }
                                                 }
        if strings.Contains(string(key),"num_pkts") {
        ipaddr := strings.Replace(string(key), "_num_pkts", "", 1)
//        fmt.Println("Found Value: "+ipaddr)
        raw_pkts, _ := client.Get(key).Result()
        num_pkts, _ := strconv.Atoi(raw_pkts)
          if num_pkts > max_pkts {
                log.Println("BAN TRIGGERED because above max_pkts: ",max_pkts)
                log.Println("Recorded requests: ", num_pkts)
                log.Println("Configuring blocking rule for "+ipaddr+"\n")
                bannedips = bannedips+ exec_shell("ipset list")
          if strings.Contains(bannedips,ipaddr) {
                log.Println("IP Already banned")
          } else {
//               ban_client.Incr(ipaddr+"_banned").Result()
                 //ban_client := redis.NewClient(&redis.Options{ Addr:     "localhost:6379",Password: "",DB: 3,    })
                 if dryrun == "false" {
                        if banmode == "ipset" { exec_shell("ipset add current_bans "+ipaddr+" timeout "+bantime)
                                                log.Println("Adding "+ipaddr+" to ipset for "+bantime)
                                                //ban_client.Set(ipaddr+"_banned",bantime,bantime,bantime*time.Second).Err()
                                                ban_client.Set(ipaddr+"_banned",bantime,time.Duration(int_bantime)*time.Second).Err()
                                        }
                                        if banmode == "trigger" {
                                                exec_shell(" trigger.sh "+ipaddr+" "+bantime+" &")
                                                log.Println("Custom Trigger script launched!!")
                                                //ban_client.Set(ipaddr+"_banned",bantime,bantime,bantime*time.Second).Err()
                                                ban_client.Set(ipaddr+"_banned",bantime,time.Duration(int_bantime)*time.Second).Err()
                                }
                                      }
                }
                        client.FlushDb()
                        }

                                                    }

        if strings.Contains(string(key),"num_bytes") {
        ipaddr := strings.Replace(string(key), "_num_bytes", "", 1)
//        fmt.Println("Found Value: "+ipaddr)
        raw_bytes, _ := client.Get(key).Result()
        num_bytes, _ := strconv.Atoi(raw_bytes)
          if num_bytes > max_bytes {
                log.Println("BAN TRIGGERED because above max_bytes: ",max_bytes)
                log.Println("Recorded requests: ", num_bytes)
                log.Println("Configuring blocking rule for "+ipaddr+"\n")
                bannedips = bannedips+ exec_shell("ipset list")
          if strings.Contains(bannedips,ipaddr) {
                log.Println("IP Already banned")
          } else {
                 if dryrun == "false" {
                 //ban_client := redis.NewClient(&redis.Options{ Addr:     "localhost:6379",Password: "",DB: 3,    })
//                      ban_client.Incr(ipaddr+"_banned").Result()
                //      ban_client.Set(ipaddr+"_banned", pkts, 0).Err()
                        if banmode == "ipset" { exec_shell("ipset add current_bans "+ipaddr+" timeout "+bantime)
                                                log.Println("Adding "+ipaddr+" to ipset for "+bantime)
                                                //bapn_client.Set(ipaddr+"_banned",bantime,bantime,bantime*time.Second).Err()
                                                ban_client.Set(ipaddr+"_banned",bantime,time.Duration(int_bantime)*time.Second).Err()
                                                }
                                                if banmode == "trigger" {
                                                exec_shell("trigger.sh "+ipaddr+" "+bantime+" &")
                                                log.Println("Custom Trigger script launched!!")
                                        //      ban_client.Set(ipaddr+"_banned",bantime,bantime,bantime*time.Second).Err()
                                                ban_client.Set(ipaddr+"_banned",bantime,time.Duration(int_bantime)*time.Second).Err()
                                }
                                      }
                }
                        client.FlushDb()
                        client.Close()
                        ban_client.Close()
                        }

                                                    }


                                                 }
}
