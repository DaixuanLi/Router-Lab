#!/bin/bash
echo "Raspbian buster is expected with bird installed"
echo "Assume eth1 is the interface to R2"
set -v
ip netns delete PC2
sleep 1
ip netns delete PC1
sleep 1
ip netns add PC2
ip l add veth-r3 type veth peer name veth-pc2
ip l set veth-pc2 netns PC2
ip netns exec PC2 ip a add 192.168.5.1/24 dev veth-pc2
ip netns exec PC2 ip l set veth-pc2 up
ip netns exec PC2 ip r add default via 192.168.5.2