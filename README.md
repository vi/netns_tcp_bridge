# netns_tcp_bridge

Special TCP forwarder (proxy) where listening part and connecing part can move to other 
Linux network namespaces using `setns(2)` call.

It is somewhat analogous to using a pair of [socat][s]s, each in different netns.

* `socat tcp-l:1234,fork,reuseaddr unix:/path/to/unix-socket-shared-between-namespaces.sock`
* `socat unix-listen:/path/to/unix-socket-shared-between-namespaces.sock tcp:127.0.0.1:1234`

It works by forking into two processes: listener and connector and by passing (`SCM_RIGHTS`) connected sockets from listener over a `socketpair(2)` to the connector process. Each part can be moved into each own network namespace.

Build it with `cargo build --release` or download it from [Github releases][gr].

# Example session

```
usual_netns# unshare --net xterm&
usual_netns# dig +short example.com               | new_netns# ip link set lo up
 93.184.216.34                                    | 
usual_netns# ip route get 93.184.216.34           | new_netns# ip route get 93.184.216.34 
 93.184.216.34 via 192.168.0.1 dev wlan0          |  RTNETLINK answers: Network is unreachable
    src 192.168.0.185 uid 0   cache               |
usual_netns# curl --head http://93.184.216.34/    | new_netns# curl --head http://93.184.216.34/
 HTTP/1.1 404 Not Found                           |  curl: (7) Couldn't connect to server
 Content-Type: text/html                          | new_netns# curl --head http://127.0.0.1/
 Date: Mon, 08 Aug 2022 23:48:10 GMT              |  curl: (7) Failed to connect to 127.0.0.1
 Server: ECS (nyb/1D07)                           |         port 80: Connection refused
 Content-Length: 345                              | new_netns# echo $$
                                                  |  6448
usual_netns# netns_tcp_bridge -l 127.0.0.1:80 \   |
                   -f /proc/6448/ns/net \         |
                   -c 93.184.216.34:80            |                          
                                                  | new_netns# curl --head http://127.0.0.1/
                                                  |  HTTP/1.1 404 Not Found
                                                  |  Content-Type: text/html
                                                  |  Date: Mon, 08 Aug 2022 23:53:32 GMT
                                                  |  Server: ECS (nyb/1D2E)
                                                  |  Content-Length: 345
```


# Limitations

* Tricky TCP features like FIN/RST distinction, OOB data are not preserved. Forwarding engine is a basic Tokio's [`copy_bidirectional`][cb].
* Single-threaded operation may limit performance.
* Non-usage of `io_uring` also limits performance - each forwarded packet is two or three syscalls.

Note that I have implemented more modes (e.g. using raw FDs), but have tested only the most straightforward mode.

[cb]:https://docs.rs/tokio/latest/tokio/io/fn.copy_bidirectional.html
[s]:http://www.dest-unreach.org/socat/
[gr]:https://github.com/vi/netns_tcp_bridge/releases/

# Usage message

```
netns_tcp_bridge --help
Usage: netns_tcp_bridge [OPTIONS]

Optional arguments:
  -h, --help
  -l, --listen LISTEN        Socket address (e.g. `127.0.0.1:1234` or `[::1]:1234`) to bind socket to.
  -L, --listen-fd LISTEN-FD  File descriptor to use as a listening socket
  -S, --preaccepted-fd PREACCEPTED-FD
                             File descriptor to use as a single connected client (skip listening and accepting loop)
  -c, --connect CONNECT      Socket address to forward incoming connections to.
  -C, --connect-fd CONNECT-FD
                             Pre-connected file descriptor to forward just one accepted connection to
  -f, --listen-netns-file LISTEN-NETNS-FILE
                             Path to a nsfs file with mounted network namespace where listening part of the forwarder should operate. E.g. /proc/1234/ns/net
  -F, --listen-netns-fd LISTEN-NETNS-FD
                             Already opened file descriptor to use for the `setns` call on listening side
  -t, --connect-netns-file CONNECT-NETNS-FILE
                             Path to a nsfs netns file to `setns` on the connecting side
  -T, --connect-netns-fd CONNECT-NETNS-FD
                             Already opened file descriptor to use for  the `setns` call on the connecting side
```

# See also

* [socketbox](https://github.com/PHJArea217/socketbox)
