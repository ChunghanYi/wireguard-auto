# wireguard-auto
WireGuard AutoConnect Client &amp; Server implemented with Modern C++

```
It's currently in development(v0.6.00). 😎

```

## How to build
```
<Ubuntu 22.04 LTS>
$ ./build.sh
 -> for x86_64 machine
...
~

$ ./build_arm64.sh
 -> for arm64 machine
...
~

$ cd build
$ ls -l
-rwxrwxr-x 1 chyi chyi 1874848  1월 22 14:52 wg_autoc
-rwxrwxr-x 1 chyi chyi 2018128  1월 22 14:51 wg_autod

$ sudo cp ./wg_autoc /usr/local/sbin
$ sudo cp ./wg_autod /usr/local/sbin
$ sudo mkdir -p /etc/wgauto
$ sudo cp ../config/client.conf /etc/wgauto
$ sudo cp ../config/server.conf /etc/wgauto

```

## How to run on Ubuntu 22.04 LTS
```
<server side>
-------------
$ sudo apt-get install redis-server
$ sudo service redis-server status
  -> install redis-server at first.
  -> The redis will store wireguard configuration information for the client.

$ sudo vi /etc/wgauto/server.conf
  -> Edit this file.
debug_mode = 1

#this part ----------------------------------------------------------
this_vpn_ip = 10.1.1.254
this_vpn_netmask = 255.255.255.0
this_public_key = "iv9OsqcIhtNACmxkxa41B7PltVIclvswY/kPCNRa4iQ="
this_endpoint_ip = 192.168.8.182
this_endpoint_port = 51820
this_allowed_ips = "10.1.1.0/24,192.168.0.0/16"

#that part ----------------------------------------------------------
vpnip_range_begin = 10.1.0.1
vpnip_range_end = 10.1.0.253
~

$ sudo /usr/local/sbin/wg_autod --help
Allowed options:
  --help                Print help message
  --version             Show version
  --daemon              Detach from the terminal(run it in background)
  --foreground          Run it in foreground
  --config arg          Set path to custom configuration file

$ sudo /usr/local/sbin/wg_autod --foreground --config /etc/wgauto/server.conf
[2025-01-22 13:08:33.373] [info] Starting the wg_autod(tcp port 51822)...
[2025-01-22 13:08:40.755] [info] >>> HELLO message received.
[2025-01-22 13:08:40.755] [info] --- Preparing vpnIP(10.1.0.2/255.255.255.0) for client.
[2025-01-22 13:08:40.755] [info] <<< HELLO message sent to client.
[2025-01-22 13:08:41.256] [info] >>> PING message received.
[2025-01-22 13:08:41.256] [info] <<< PONG message sent to client.
[2025-01-22 13:08:41.259] [info] szInfo -----> [wg set wg0 peer 6L9YraonVAB90h+dxhKEumHUQh5wjqSmemOs1PGvgwE= allowed-ips 172.16.1.100/32 endpoint 192.168.8.205:51820 persistent-keepalive 25 &]
[2025-01-22 13:08:41.259] [info] OK, wireguard setup is complete.
...

$ redis-cli
127.0.0.1:6379> keys wgac*
1) "wgac:7456.3caf.889d"
127.0.0.1:6379> get wgac:7456.3caf.889d
"10.1.0.1 255.255.255.0 ON8X17qJWTthbc1KTxxdvR0RvSCdSDf7TXaYYi/2YS4= 192.168.8.205:51820 10.1.1.0/24,192.168.0.0/16"
127.0.0.1:6379>

<client side>
--------------
$ sudo vi /etc/wgauto/client.conf
  -> Edit this file.
debug_mode = 1

#this part ----------------------------------------------------------
this_vpn_ip = 10.1.1.100	#Actually, this value will be given by server automatically.
this_vpn_netmask = 255.255.255.0
this_public_key = "6L9YraonVAB90h+dxhKEumHUQh5wjqSmemOs1PGvgwE="
this_endpoint_ip = 192.168.8.205
this_endpoint_port = 51820
this_allowed_ips = "10.1.1.0/24,192.168.0.0/16"
~

$ sudo /usr/local/sbin/wg_autoc --help
Allowed options:
  --help                Print help message
  --version             Show version
  --daemon              Detach from the terminal(run it in background)
  --foreground          Run it in foreground
  --server arg          Specify the server ip address
  --config arg          Set path to custom configuration file

$ sudo /usr/local/sbin/wg_autoc --foreground --server 127.0.0.1 --config /etc/wgauto/client.conf
[2025-01-22 13:09:06.870] [info] Client connected successfully
[2025-01-22 13:09:06.870] [info] >>> HELLO message sent to server.
[2025-01-22 13:09:07.370] [info] <<< HELLO message received.
[2025-01-22 13:09:07.371] [info] --- vpnIP(10.1.0.3/255.255.255.0) received from server.
[2025-01-22 13:09:07.371] [info] >>> PING message sent to server.
[2025-01-22 13:09:07.871] [info] <<< PONG message received.
[2025-01-22 13:09:07.874] [info] szInfo -----> [wg set wg0 peer iv9OsqcIhtNACmxkxa41B7PltVIclvswY/kPCNRa4iQ= allowed-ips 172.16.1.254/32 endpoint 192.168.8.182:51820 persistent-keepalive 25 &]
[2025-01-22 13:09:07.874] [info] OK, wireguard setup is complete.
^C  <------------ by user input
[2025-01-22 13:22:29.397] [info] >>> BYE message sent to server.
[2025-01-22 13:22:29.897] [info] <<< BYE message received.
[2025-01-22 13:22:29.901] [info] szInfo -----> [wg set wg0 peer iv9OsqcIhtNACmxkxa41B7PltVIclvswY/kPCNRa4iQ= remove]
[2025-01-22 13:22:29.902] [info] OK, wireguard rule is removed.
[2025-01-22 13:22:30.902] [info] Closing wg_autoc...
[2025-01-22 13:22:30.902] [info] Client closed.
...
```

## My blog posting for this project
  For more information, please refer to my blog post below.<br>
  https://slowbootkernelhacks.blogspot.com/2025/01/modern-c-quantum-resistant-wireguard.html
  <br>

## Reference codes
```
<Simple-TCP-Server-Client-CPP-Example>
  https://github.com/elhayra/tcp_server_client

<Fast C++ logging library>
  https://github.com/gabime/spdlog

<Boost library>
  https://www.boost.org/releases/latest

<FastNetMon>
  https://github.com/pavel-odintsov/fastnetmon

<wireguard-tools>
  https://github.com/WireGuard/wireguard-tools

<libsodium>
  https://github.com/jedisct1/libsodium

<hiredis>
  https://github.com/redis/hiredis

<C++20 STL cookbook examples>
  https://github.com/PacktPublishing/CPP-20-STL-Cookbook

```
  <br>

  __WireGuard is a registered trademark of Jason A. Donenfeld.__
