#!/bin/bash

sudo ifconfig ens33:0 down
sudo ifconfig ens33:1 down
sudo ifconfig ens33:2 down
sudo ifconfig ens33:3 down
sudo ifconfig ens33:4 down
sudo ifconfig ens33:5 down

sudo iptables -D OUTPUT 1
