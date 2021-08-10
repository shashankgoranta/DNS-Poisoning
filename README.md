# DNS-Poisoning
This repository contains two tools.
1) An on-path DNS poisoning attack tool
2) A passive DNS poisoning attack detector. Both tools are developed in Go using the GoPacket library, and support just plain (UDP) DNS traffic over port 53.

1. DNS Poisioning tool:
DNS packet injector, named 'dnspoison', captures the traffic from a network interface in promiscuous mode, and injects forged responses to selected DNS A requests with the goal of poisoning the cache of the victim's resolver.

Specifications of the program:

go run dnspoison.go [-i interface] [-f hostnames] [expression]

-i  Listen on network device <interface> (e.g., eth0). If not specified,
    dnspoison should select a default interface to listen on. The same
    interface should be used for packet injection.

-f  Read a list of IP address and hostname pairs specifying the hostnames to
    be hijacked. If '-f' is not specified, dnspoison should forge replies to
    all observed requests with the chosen interface's IP address as an answer.

The optional <expression> argument is a BPF filter that specifies a subset of
the traffic to be monitored. This option is useful for targeting a single
victim or a group of victims.
  
The <hostnames> file should contain one IP and hostname pair per line.
  
2. DNS Detection tool:
The tool captures the traffic from a network interface in promiscuous mode and detects
DNS poisoning attack attempts. Detection is based on
identifying duplicate responses within a short time interval towards the same
destination, which contain different answers for the same A request (i.e., the
observation of the attacker's spoofed response and the server's actual
response). an alert is raised
irrespectively of whether the attacker's spoofed response arrived before or
after the real response.

Specifications of the program:

go run dnsdetect.go [-i interface] [-r tracefile] expression

-i  Listen on network device <interface> (e.g., eth0). If not specified,
    the program should select a default interface to listen on.

-r  Read packets from <tracefile> (tcpdump format). Useful for detecting
    DNS poisoning attacks in existing network traces.

<expression> is a BPF filter that specifies a subset of the traffic to be
monitored.

Once an attack is detected, dnsdetect should print to stdout a detailed alert
containing a printout of both the spoofed and legitimate responses.  
