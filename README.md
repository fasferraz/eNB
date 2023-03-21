# eNB s1 Emulator
## Installation

On a Ubuntu systems you can install with:
```
apt-get install -y python3-pip libsctp-dev swig python3-pyscard git net-tools bridge-utils
sysctl -w net.ipv4.ip_forward=1
```

Now we can clone the repository with:

```
cd /root/
git clone https://github.com/avmalavi/eNB.git 
cd eNB
```

Finally we will need to install all of the Python packages needed to run the tool.

We can install all these packages using Pip3 with:

```
sudo pip3 install -r requirements.txt
```

## Usage

Many variables needed for SA1P and NAS are defined inside the *session_dict_initialization* function.
You can change them to meet your own needs.

When you call the script these are the options available:

```
./simulator.py -P start-simulator --enbip 192.168.197.180 --mmeip 192.168.197.201
./simulator.py -P s1-setup --mcc 111 --mnc 111 --enbid 100000 --tac1 63 --tac2 64
./simulator.py -P attach --mcc 111 --mnc 111 --imsi 111111000000001 --key e8767ccf27d3fae385b16bf073c912a2 --opc 982559004308ee438a99b5baf6a59c45
./simulator.py -P idle --imsi 111111000000001
./simulator.py -P tau --imsi 111111000000001
./simulator.py -P tau-p --imsi 111111000000001
./simulator.py -P service-request --imsi 111111000000001
./simulator.py -P detach --imsi 111111000000001
./simulator.py -P stop-simulator
  
  ```

Run Data using netns Example for data 
```
ip netns exec 111111000000001 ping 8.8.8.8
```

For Multiple User attach:
```
./simulator.py -P start-simulator --enbip 192.168.197.180 --mmeip 192.168.197.201
./simulator.py -P s1-setup --mcc 111 --mnc 111 --enbid 100000 --tac1 63 --tac2 64
./simulator.py -P attach --mcc 111 --mnc 111 --imsi 111111000000001 --key e8767ccf27d3fae385b16bf073c912a2 --opc 982559004308ee438a99b5baf6a59c45
./simulator.py -P attach --mcc 111 --mnc 111 --imsi 111111000000002 --key e8767ccf27d3fae385b16bf073c912a3 --opc 982559004308ee438a99b5baf6a59c46
./simulator.py -P attach --mcc 111 --mnc 111 --imsi 111111000000003 --key e8767ccf27d3fae385b16bf073c912a4 --opc 982559004308ee438a99b5baf6a59c47
./simulator.py -P detach --imsi 111111000000001
./simulator.py -P detach --imsi 111111000000002
./simulator.py -P detach --imsi 111111000000003
./simulator.py -P stop-simulator
  
  ```
The basic flow could be for example, option 15 - to bring up the s1 interface, and then option 20 - to perform attach.
##
log path :- /var/log/sim/

## Functionality

The application supports currently the following options:

- S1 Setup type: LTE, NB-IoT, or both
- Mobile Identity Type: IMSI or GUTI
- Attach PDN: Default APN, or Specific APN
- Session Type: 4G, 5G or NB-IoT
- Session Sub-Type: No PSM and No eDRX, PSM, eDRX or both PSM and eDRX
- PDN Type ipv4, ipv6, ipv4v6 or Non-IP
- Control Plane Service Request with Radio Bearer or without Radio Bearer
- Attach Type: EPS Attach, Combined EPS/IMSI Attach or Emergency Attach
- TAU Type: TA Updating, Combined TA/LA Updating or Combined TA/LA Updating with IMSI Attach
- Process Paging: Enabled or Disabled
- SMS Update type: Additional Update Type SMS Only: False or True
- eNB Cell and TAC can change
- P-CSCF Restoration Support capability

In terms of procedures, the application supports the following ones:

- S1 Setup Request
- S1 Reset
- Attach
- Detach
- TAU
- TAU Periodic
- Service Request
- UE Context Release
- Send SMS (a predefined one)
- Control Plane Service Request
- E-RAB Modification Indication (5G)
- Secondary RAT Data Usage Report (5G)
- PDN Connectivity
- PDN Disconnect
- Activate/Deactivate GTP-U for Control Plane
- Activate/Deactivate Data over NAS
- Set/Send Non-IP Packet
 


