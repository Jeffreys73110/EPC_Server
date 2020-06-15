# LTE_Server

The server support basic initial attach and volte functions.
The version is developed based on the purpose of feasibility verification of internal calls of cell phones, so the server is somewhat unstable, incomplete.
The server includes Mobility Management Entity (MME), Serving and Packet Data Network Gateway (SPGW).

## Architecture
```
    ┌───────────────┐       ┌───────────────┐       ┌───────────────┐       ┌───────────────────┐       ┌───────────────┐
    │               │       │               │       │               │       │                   │       │               │
    │               │       │               │       │               │       │                   │       │               │
    │       UE      ├──────▶│       eNB     ├──────▶│       MME     ├──────▶│        GW/PGW     ├──────▶│     P_CSCF    │
    │               │       │               │       │               │       │                   │       │               │
    │               │       │               │       │               │       │                   │       │               │
    │               │       │               │       │               │       │                   │       │               │
    └───┬───────────┘       └───┬───────────┘       └───┬───────────┘       └───┬───────────┬───┘       └───┬───────────┘
        │                       │                       │                       │           │               │
        │                       │                       │                       │           │               │
        │                   ────▼───────────────────────▼───────────────────────▼──         │               │
        │                 10.102.81.59            10.102.81.100           10.102.81.102     │               │
        │                                            (MME_IP)                 (SGW_IP)      │               │
        │                                                                                   │               │
    ────▼───────────────────────────────────────────────────────────────────────────────────▼───────────────▼───
     (PDN_IP)                                                                            (PGW_IP)       (P_CSCF_IP)

```

## OS
ubuntu 18.04

## Installation and Configuration
* set network environment
	```shell
 	 $ sudo sh setip.sh
	```
* Adjust configuration
	```shell
	# edit parameters and save file function
	$ vim config.h
	```

* Build code and run
	```shell
	# build code
	$ make

	# run server
	$ sudo ./a.out
	```

* unset network environment
	```shell
  	$ sudo sh unset_ip.sh
	```




## Troubleshooting
#### Program crash
Debug or re-execute the server.