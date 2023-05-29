How to make packet forward:

iptables -t nat -A PREROUTING -p udp -d <IP> --dport 53 -j DNAT --to-destination <IP>:<PROXY_PORT>
iptables -L -t nat

To save way #1 (may not work):
    iptables-save > /etc/iptables.rules
    iptables-restore < /etc/iptables.rules
    vi /etc/network/if-pre-up.d/iptables:
        #!/bin/bash
        PATH=/etc:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
        iptables-restore < /etc/iptables.rules
        exit 0 

To save way #2:
    sudo apt-get install iptables-persistent
    sudo netfilter-persistent save
    sudo netfilter-persistent reload