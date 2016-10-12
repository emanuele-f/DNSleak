# DNSleak

When using VPN or other tunneling softwares, a misconfigured system can often lead to DNS requests
being sent *outside* the tunnel. This means that, even if applicative information is protected, the sites
you visit and the applications you use can be inferred by inspencting the plain DNS packets, and of course this
is not what you want.

DNSleak can detect a misconfigured system where DNS packets are leaked. Unlike many other web-based softwares,
it works at the local computer level. No third party servers are used and DNS leak result is a true / false response.

How it works
------------
DNSleak requests network address translation using the glibc interface. At the same time, it listens for DNS packets
coming out from the local network interface. Captured DNS packets are inspected using the
[nDPI](https://github.com/ntop/nDPI) library.

When a request for a given host name *X_HOST* is performed and a DNS packet with *X_HOST* as query is captured,
a leak is detected.

Installation
------------

You need the nDPI library to be installed system-wide in order to compile the program. Beware of using your
distribution provided package, which could be too outdated.

In order to compile and install run:
```
make && PREFIX=/usr make install
```

To execute the command, just run ```sudo dnsleak```, followed by the network interface you are
using to communicate "outside" (e.g. wlan0). Please note that this is *not* the tunnel interface used
to route the packets (e.g. tun0).

Run the command without arguments to get the list of available options.

Examples
--------

Quick test: 1 on leak, 0 otherwise
```
sudo dnsleak wlan0 | grep -c "=== Leaks detected ==="
```
5 minutes test, 5 seconds interval: 1 on leak, 0 otherwise
```
sudo dnsleak wlan0 -c 60 -i 5000 | grep -c "=== Leaks detected ==="
```
