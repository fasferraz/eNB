#!/usr/bin/python3
from ipcqueue import posixmq
from optparse import OptionParser
import threading
import sys
import time
import random
import os

dic={}
parser = OptionParser()
parser.add_option("-P", "--procedure", dest="process", help="starting simulator")
parser.add_option("-I", "--enbip", dest="enb_ip", help="eNB Local IP Address")
parser.add_option("-M", "--mmeip", dest="mme_ip", help="MME IP Address")
parser.add_option("-S", "--imsi", dest="imsi", help="IMSI (15 digits)")
parser.add_option("-K", "--key", dest="ki", help="ki for Milenage (if not using option -u)")  
parser.add_option("-C", "--opc", dest="opc", help="opc for Milenage (if not using option -u)")  
parser.add_option("-L", "--mcc", dest="mcc", help="Operator MCC")
parser.add_option("-N", "--mnc", dest="mnc", help="Operator MNC")
parser.add_option("-A", "--apn", dest="apn", help="Operator APN")
parser.add_option("-T", "--tac1", dest="tac1", help="Operator TAC1")
parser.add_option("-V", "--tac2", dest="tac2", help="Operator TAC2")
parser.add_option("-E", "--enbid", dest="enb_id", help="Enodeb id")
(options, args) = parser.parse_args()
if len(sys.argv) <= 1:
       print("No arguments passed - You need to specify parameters to use.")
       parser.print_help()
       exit(1)
if options.process is not None:
    dic['procedure'] = str(options.process)
if options.enb_ip is not None:
    dic['enb_ip'] = str(options.enb_ip)
if options.mme_ip is not None:
    dic['mme_ip'] = str(options.mme_ip)
if options.imsi is not None:
    dic['imsi'] = str(options.imsi)
if options.ki is not None:
    dic['ki'] = str(options.ki)
if options.opc is not None:
    dic['opc'] = str(options.opc)
if options.mcc is not None:
    dic['mcc'] = str(options.mcc)  
if options.mnc is not None:
    dic['mnc'] = str(options.mnc)  
if options.apn is not None:
    dic['apn'] = str(options.apn) 
if options.tac1 is not None:
    dic['tac1'] = str(options.tac1)
if options.tac2 is not None:
    dic['tac2'] = str(options.tac2)
if options.enb_id is not None:
    dic['enb_id'] = str(options.enb_id)

# Function to validate linux command execution status
def linux_command(command):
    result= os.system(command)
    if result != 0:
        print (f'linux command  "{command}" failed')
        sys.exit()

# Func to send procedures
def msg_queue(user_dic):
    q=posixmq.Queue("/foo")
    q.put(user_dic)

# Func to start simulator
def start_sim(enb,mme):
    service_template=["[Unit]","Description=Simulator Service",
                      "[Service]","Restart=always","User=root","WorkingDirectory=/root/eNB/","ExecStart=/usr/bin/python3 /root/eNB/eNB_LOCAL.py ",
                      "[Install]","WantedBy=multi-user.target"]
    with open("/lib/systemd/system/tool.service","w") as toolsvc:
        for content in service_template:
            if "ExecStart" in content:
                toolsvc.write(f"{content} -i {enb} -m {mme} \n")
            else:
                toolsvc.write(f"{content} \n")
    linux_command("sudo systemctl daemon-reload ")
    linux_command("sudo service tool start")
    linux_command("sudo systemctl enable tool --now")

# Func to stop simulator
def stop_sim():
    linux_command("sudo service tool stop")
    linux_command("rm -rf /lib/systemd/system/tool.service")
    linux_command("sudo systemctl daemon-reload")

if dic['procedure'] == "start-simulator":
    start_sim(dic['enb_ip'],dic['mme_ip']) 
elif dic['procedure'] == "stop-simulator":
    stop_sim()  
elif 'procedure' in dic:
    msg_queue(dic)

