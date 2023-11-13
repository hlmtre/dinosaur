#!/usr/bin/env bash

modprobe dummy
ip link add du0 type dummy
ip addr add 172.16.35.1/24 dev du0
