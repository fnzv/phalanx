# phalanx
DDos dedection and mitigation system written in Go (Experimental)

![](phalanx-grafana.png?raw=true)

### Project components:
- collectord
- detectord
- viewer


1) collectord is the daemon responsible to collect Netflow or Pcap data and forward it to Redis for post-analysis. <br>
   When configured on "host-based" mode the collector will gather data from an attached interface (via libpcap.. don't use it on high traffic rates) and send all the occurencies of an IP address to Redis <br> (Example 100 requests from 8.8.8.8 --> will create on redis 8.8.8.8 --> 100 ).<br>
   If Netflow is configured the collector will read all the netflow v9 records from port 0.0.0.0:9995 and send them into redis with the same logic but this time we take note also of Packets and Bytes sent by the IP address.<br>
   An Influx output can be configured to collect Netflow data such as network Throughput,Packets,Requests. (If empty the collector won't do nothing) <br><br>

2) detectord reads all the collected data from Redis and apply the thresholds defined in the configuration file (detector.conf).
   Bans can result into ipset rules added into the current host or trigger a bash script to launch remote commands/tools (ssh into machine, shutoff, bgp announce) <br><br>


3) viewer is a client that reads current information from redis and prints it on screen (current bans, packets and bytes if netflow is enabled) <br><br>



### Requirements:
```
- All golang deps & golang
- sudo apt-get install libpcap0.8-dev
- redis-server
- (optional) influxdb and grafana for dashboarding https://grafana.com/dashboards/4208
```

### Install
- Git clone project into the machine
- Get all deps with: ``` go get -d ./... ```
- Edit config files under conf/  (Example.. choose between host-based or netflow..thresholds.. on both conf files)
- Build time!!  ``` go build detectord.go && go build collectord.go && go build viewer.go ```
- Start the services: ``` ./service start ``` and to stop them ``` ./service stop ``` or kill processes via ```killall collectord && killall detectord ```


### Scenarios
- Host-based:
  Install Phalanx on Front-End machine that distribute traffic to a few web servers of a constant targeted site by Applicative DDoS attacks (Reaching maximum Apache workers or php fpm processes) from bots or crawlers (Add to whitelist all customers and "clean" IPs) then let Phalanx ban via configured thresholds.
  
- Netflow:
  Get Netflow traffic from router or a configured linux box (An easy way to export nf from linux machines is: https://github.com/aabc/ipt-netflow ) to the machine where Phalanx is configured (port 9995) then after configured the thresholds you can call an external trigger (trigger.sh) to push some remote configurations (ssh into box + shutdown|/bgp announce|/set ipt|/shutoff via hypervisor API) or just notify your Slack/Telegram channel about it.
  
<br><br>  

If you have any cool idea/problem just open an issue and i'll look into it.<br>
<br> <br> 
### Known issues
 - Netflow parse doesn't work on all netflow v9 records (tested on ipt and cisco nf export without issues)






