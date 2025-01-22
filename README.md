# wireguard-auto
WireGuard AutoConnect Client &amp; Server implemented with Modern C++

```
It's currently in development(v0.1.99). 😎

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

$ cd build
$ ls -l
-rwxrwxr-x 1 chyi chyi 1874848  1월 22 14:52 wg_autoc
-rwxrwxr-x 1 chyi chyi 2018128  1월 22 14:51 wg_autod

```

## How to run on Ubuntu 22.04 LTS
```
<server side>
$ sudo ./wg_autod -f ../config/server.conf 
[2025-01-22 13:08:33.373] [info] Starting the wg_autod(tcp port 51822)...
[2025-01-22 13:08:40.755] [info] >>> HELLO message received.
[2025-01-22 13:08:40.755] [info] <<< HELLO message sent to client.
[2025-01-22 13:08:41.256] [info] >>> PING message received.
[2025-01-22 13:08:41.256] [info] <<< PONG message sent to client.
[2025-01-22 13:08:41.259] [info] szInfo -----> [wg set wg0 peer 6L9YraonVAB90h+dxhKEumHUQh5wjqSmemOs1PGvgwE= allowed-ips 172.16.1.100/32 endpoint 192.168.8.205:51820 persistent-keepalive 25 &]
[2025-01-22 13:08:41.259] [info] OK, wireguard setup is complete.
...

<client side>
$ sudo ./wg_autoc -f 127.0.0.1 ../config/client.conf
[2025-01-22 13:09:06.870] [info] Client connected successfully
[2025-01-22 13:09:06.870] [info] >>> HELLO message sent to server.
[2025-01-22 13:09:07.370] [info] <<< HELLO message received.
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

## How to install on NanoPi R5S or Gl-iNet MT2500 
```
<TBD>

--------------------
Good luck~
Slowboot
```

## My blog posting for this project
  For more information, please read the blog posting below.<br>
  <br>

## Reference codes
```
<Simple-TCP-Server-Client-CPP-Example>
  https://github.com/elhayra/tcp_server_client

<Fast C++ logging library>
  https://github.com/gabime/spdlog
```
  <br>

  __WireGuard is a registered trademark of Jason A. Donenfeld.__
