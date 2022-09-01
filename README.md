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
code blocks for commands
```

## Help

Any advise for common problems or issues.
```
command to run if program contains helper info
```

## Authors

Contributors names and contact info

ex. Dominique Pizzie  
ex. [@DomPizzie](https://twitter.com/dompizzie)

## Version History

* 0.2
    * Various bug fixes and optimizations
    * See [commit change]() or See [release history]()
* 0.1
    * Initial Release

## License

This project is licensed under the [NAME HERE] License - see the LICENSE.md file for details

## Acknowledgments

Inspiration, code snippets, etc.
* [awesome-readme](https://github.com/matiassingers/awesome-readme)
* [PurpleBooth](https://gist.github.com/PurpleBooth/109311bb0361f32d87a2)
* [dbader](https://github.com/dbader/readme-template)
* [zenorocha](https://gist.github.com/zenorocha/4526327)
* [fvcproductions](https://gist.github.com/fvcproductions/1bfc2d4aecb01a834b46)
