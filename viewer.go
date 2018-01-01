package main

import (

        "time"
        "fmt"
        "strings"
        "github.com/go-redis/redis"
)



func main () {


var keys []string
var kkeys []string
var cursor uint64
var ccursor uint64
var n int
var nn int
var i int

        client := redis.NewClient(&redis.Options{
                Addr:     "localhost:6379",
                Password: "", // no password set
                DB:       1,  // use default DB
        })

        ban_client := redis.NewClient(&redis.Options{
                Addr:     "localhost:6379",
                Password: "", // no password set
                DB:       2,  // use default DB
        })
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

for {
    var err error
    kkeys, ccursor, err = ban_client.Scan(cursor, "", 100).Result()
    if err != nil {
        panic(err)
    }
    nn += len(keys)
    if ccursor == 0 {
        break
    }

}

for {
    for _, key := range keys {

        if strings.Contains(string(key),"total_pkts") {
                total_raw_pkts, _ := client.Get(key).Result()
                total_pkts := string(total_raw_pkts)
                fmt.Println("Total recorded packets: "+total_pkts)
                                                }
        if strings.Contains(string(key),"total_bytes") {
                total_raw_bytes, _ := client.Get(key).Result()
                total_bytes := string(total_raw_bytes)
                fmt.Println("Total recorded Bytes: "+total_bytes)
                                                }
        if strings.Contains(string(key),"total_reqs") {
                total_raw_reqs, _ := client.Get(key).Result()
                total_reqs := string(total_raw_reqs)
                fmt.Println("Total recorded requests: "+total_reqs)
                                                }
//        fmt.Println(i)
}

   fmt.Println("Active Bans")
   for _, kkey := range kkeys {
      if strings.Contains(string(kkey),"banned") {

                //ipaddr := strings.Replace(string(kkey), "_banned", "", 1)
                num_times := ban_client.TTL(kkey)
                fmt.Println(num_times.String())
                                                }
}
          time.Sleep(time.Second)
          i++
          if i % 10 == 0 { client.FlushDb()
                fmt.Println("Flushing redis")
                }
          print("\033[H\033[2J")
 }




}
