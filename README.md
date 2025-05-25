This document is the manual of doing this homework.

We need to make a packet filter through RAW socket.

Several things need to be done:
1. use docket-compose to build four containers.
    - 192.168.2.1 ~ 192.168.2.4
2. allow all packets from 192.168.2.4 to 192.168.2.1
3. block all packets from 192.168.2.3 to 192.168.2.1
4. need a tutorial