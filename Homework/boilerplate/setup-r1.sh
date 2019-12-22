#!/bin/bash
echo "Raspbian buster is expected with bird installed"
echo "Assume eth1 is the interface to R2"
set -v

# Remove if it exists
ip netns delete PC1
sleep 1
ip netns delete PC2
sleep 1


# Setup PC1
ip netns add PC1
ip l add veth-r1 type veth peer name veth-pc1
ip l set veth-pc1 netns PC1
ip netns exec PC1 ip a add 192.168.1.2/24 dev veth-pc1
ip netns exec PC1 ip l set veth-pc1 up
ip netns exec PC1 ip r add default via 192.168.1.1
