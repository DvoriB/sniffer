# sniffer

Sniffer to detect SYN flood attack.

## Description

The sniffer sits on a network device selected by the user, receives the packets, detects dDoS attacks in the TCP protocol and blocks them.
The detection is done by mapping packets and blocking IP addresses that sent many initial handshake calls in a short period of time.
Each packet is captured by the PCAP and the relevant data is saved in the SQLIT DB.
If the packet comes from a previously blocked IP address, it is ignored. The packet is then checked to see if it is an initial handshake (SYN=1). If so, it is inserted into a hash table that stores all the IP addresses of the sources of the packets that are initial handshakes together with the amount of clicks from each IP.
If the amount of requests from that IP exceeds a certain amount, the address is blocked using the IPTABLE command and is saved in a hash table of blocked IP addresses and in the table of blocked IP addresses in the DB.
The hash table is reset every period of time in order to detect an increased amount of requests at a certain time.
We have enabled a user interface using the ^C signal that presents the user with an opportunity to get a glimpse of the program's operation.

## Getting Started

### Dependencies

* Describe any prerequisites, libraries, OS version, etc., needed before installing program.
* ex. Windows 10

### Installing

* git clone 
* "sudo apt install clang"
* "sudo apt install sqlite3 libsqlite3-dev"
* "sudo apt-get install git libpcap-dev"
* "sudo apt install net-tools"
### Executing program

* How to run the program
* Step-by-step bullets
```
make
sudo ./run
```

## Help

Any advise for common problems or issues.
```
command to run if program contains helper info
```

## Authors

Contributors names and contact info

ex. Yael Hviv
ex. Racheli Hadad
ex. Nechami Weiss
ex. Dvori Blatt

## Acknowledgments

Inspiration, code snippets, etc.
* [threadpool-packet-sniffe](https://github.com/joverandout/threadpool-packet-sniffer)

