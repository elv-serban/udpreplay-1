# udpreplay

## Usage

```
usage: udpreplay [-i iface] [-l] [-s speed] [-c millisec] [-r repeat] [-t ttl] [-h ip] [-p port] pcap

  -i iface    interface to send packets through
  -l          enable loopback
  -c millisec constant milliseconds between packets
  -r repeat   number of times to loop data
  -s speed    replay speed relative to pcap timestamps
  -t ttl      packet ttl
  -b          enable broadcast (SO_BROADCAST)
  -h          destination IP address
  -p          destination port
```

## Example

```

  ./udpreplay -h 127.0.0.1 -p 9000 my.cap

  ./udpreplay -h 235.0.0.1 -p 9000 my.cap

```

## Build


```
  make
```

## About

Initially forked from: https://github.com/rigtorp/udpreplay

