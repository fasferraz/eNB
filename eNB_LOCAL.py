from scapy.all import *
import re
import netifaces
from ipcqueue import posixmq
import random
import socket
import struct
import time
import select
from optparse import OptionParser
from pycrate_asn1dir import S1AP
from pycrate_asn1rt.utils import *
from binascii import hexlify, unhexlify
from CryptoMobile.CM import *
from CryptoMobile.Milenage import Milenage
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
import sys
import fcntl
import os
import subprocess
from threading import Thread
import datetime
import logging
from kamene.all import IP
from kamene.all import UDP 
from kamene.all import Raw
from kamene.all import send 
import multiprocessing
import eNAS, eMENU
os.system("mkdir -p /var/log/sim/")
logging.basicConfig(filename="/var/log/sim/tool.log",filemode='w',format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',datefmt='%Y-%m-%d %H:%M:%S',level=logging.DEBUG)
logger = logging.getLogger('edge_log')


#tries to import all options for retrieving IMSI, and RES, CK and IK from USIM.
#if all fails, return_imsi and return_res_ck_ik will return None, so local values will be used.
try:
   import serial
except:
    pass
try:
    from smartcard.System import readers
    from smartcard.util import toHexString,toBytes
    try:
        from card.USIM import *
    except:
        pass
except:
    pass
try:    
    import requests
    requests.packages.urllib3.disable_warnings()
except:
    pass
    

def flag_set(n):
    if (n % 2) == 0:
      return False
    else:
      return False
enb_s1ap_id= 1000
PLMN = '111111'
IMSI = PLMN + '1234567890'
IMEISV = '1234567890123456'
IMEI = '123456789012347'
APN = 'internet'

#Examples. Customize at your needs
NON_IP_PACKET_1 = '0102030405060708090a'
NON_IP_PACKET_2 = '0102030405060708090a0102030405060708090a'
NON_IP_PACKET_3 = '0102030405060708090a0102030405060708090a0102030405060708090a'
NON_IP_PACKET_4 = '0102030405060708090a0102030405060708090a0102030405060708090a0102030405060708090a'

#   session_dict structure
#
#    session_dict['STATE'] = 0
#   
#    enb info:
#    session_dict['ENB-UE-S1AP-ID']
#    session_dict['ENB-NAME'] = string with enb nasme
#    session_dict['ENB-PLMN'] = plmn
#    session_dict['ENB-TAC'] = tac
#    session_dict['ENB-ID'] = enb_id
#    session_dict['ENB-CELLID']  = enb cellid
#    session_dict['ENB-GTP-ADDRESS-INT'] = ip address in integer format to use directly in s1ap
#    
#    security:   
#    session_dict['ENC-ALG'] = encryption algorithm 0 to 3
#    session_dict['INT-ALG'] = integrity algorithm 1 to 3 
#    session_dict['ENC-KEY'] = encryption key
#    session_dict['INT-KEY'] = integrity key 
#    session_dict['XRES'] = xres
#    session_dict['KASME'] = kasme
#    session_dict['NAS-KEY-EEA1'] 
#    session_dict['NAS-KEY-EEA2'] 
#    session_dict['NAS-KEY-EEA3'] 
#    session_dict['NAS-KEY-EIA1'] 
#    session_dict['NAS-KEY-EIA2'] 
#    session_dict['NAS-KEY-EIA3']    
  
#    mme info:
#    session_dict['MME-NAME'] = mme_name
#    session_dict['MME-PLMN'] = servedPLMNs
#    session_dict['MME-GROUP-ID'] = servedGroupIDs
#    session_dict['MME-CODE'] = servedMMECs
#    session_dict['MME-RELATIVE-CAPACITY'] 0 relative capacity
#    session_dict['MME-UE-S1AP-ID'] = mme_ue_s1ap_id
#
#    nas:
#    session_dict['NAS'] = full nas_pdu (either received or to ber sent, header, mac, sqn, and nas ecnrypted or not)
#    session_dict['NAS-ENC'] = nas_pdu encrypted (either received or to ber sent, and can be ecnrypted)
#    session_dict['UP-COUNT'] = count (integer) . sqn is the last byte %256
#    session_dict['DOWN-COUNT'] = count (integer) . sqn is the last byte %256. from the received
#    session_dict['DIR'] = 0 or 1 direction 0 uplink, 1 downlink
#     
#    session_dict['NAS-SMS-MT'] = nas for Answering to SMS-MT
######################################################################################################################################
#                                                       GENERAL PROCEDURES:                                                          #
######################################################################################################################################

def add_ns(ns_name,veth,nseth,ue_ip):
    sys_ns=os.popen("ip netns show").read()
    if ns_name in sys_ns:
        os.popen(f"ip netns del {ns_name}")
    os.popen(f"ip netns add {ns_name}")
    veth_ns=os.popen(f"ip link show type veth").read()
    if veth in veth_ns:
        os.popen(f"ip link del {veth}")
    os.popen(f"ip link add {veth} type veth peer name {nseth}")
    veth_exists=os.popen("ip link show type veth").read()
    if veth in veth_exists and nseth in veth_exists:
        logging.info("veth added successfully")
    os.system(f"ip link set {nseth} netns {ns_name}")
    os.system(f"ip netns exec {ns_name} ifconfig {nseth} {ue_ip}/24 up")
    os.system(f"ip link set dev {veth} master {bridge_name}")
    os.system(f"ip link set dev {veth} up")
    os.system(f"ip netns exec {ns_name} ip  link set  lo up")
    try:
        br_ip_list=[n['addr'] for n in netifaces.ifaddresses(bridge_name)[2] ]
    except:
        br_ip_list=[]
    subnet=re.findall(r"[\d]*.[\d]*.[\d]*.",ue_ip)[0]
    if f"{subnet}1" not in br_ip_list:
        os.popen(f"ip addr add {subnet}1/24 dev {bridge_name}")
    os.popen(f"ip netns exec {ns_name} ip route add default via {subnet}1 dev {nseth}")

def delete_ns(ns_name,veth):
    sys_ns=os.popen("ip netns show").read()
    if ns_name in sys_ns:
        os.popen(f"ip netns del {ns_name}")

def bridge_up():
    os.system(f"ip link del {bridge_name} ")
    os.system(f"ip link add {bridge_name} type bridge")
    os.system(f"ip link set dev {bridge_name} up")

def ue_eth_pair(ue_pair_val=None):
    global ue_eth
    if ue_pair_val is None:
        return ue_eth.pop(0)
    else:
        ue_eth.append(ue_pair_val)

def upteid_get():
    global upteid
    if upteid == 100000:
        upteid = 1
    else:
        upteid+=1
    return upteid

def session_dict_initialization(session_dict):

    session_dict['STATE'] = 0
    session_dict['ENB-UE-S1AP-ID'] = random.randint(1000, 2000)
    session_dict['ENB-NAME'] = 'Fabricio-eNB'
    session_dict['ENB-PLMN'] = return_plmn_s1ap(session_dict['PLMN'])
    session_dict['XRES'] = b'xresxres'

    session_dict['KASME'] = b'kasme   kasme   kasme   kasme   '
    # hex: 6b61736d652020206b61736d652020206b61736d652020206b61736d65202020
 
    session_dict['ENB-GTP-ADDRESS-INT'] = ''
    
    session_dict['RAB-ID'] = []
    session_dict['SGW-GTP-ADDRESS'] = []
    session_dict['SGW-TEID'] = []
    
    session_dict['EPS-BEARER-IDENTITY'] = []
    session_dict['EPS-BEARER-TYPE'] = []  # default 0, dedicated 1
    session_dict['EPS-BEARER-STATE']  = [] # active 1, inactive 0
    session_dict['EPS-BEARER-APN'] = []
    session_dict['PDN-ADDRESS'] = []

    session_dict['PDN-ADDRESS-IPV4'] = None
    session_dict['PDN-ADDRESS-IPV6'] = None
    
    if session_dict['ENB-TAC1'] is None:
        session_dict['ENB-TAC1'] = b'\x00\x01'
    if session_dict['ENB-TAC2'] is None:
        session_dict['ENB-TAC2'] = b'\x00\x03'
    session_dict['ENB-TAC'] = session_dict['ENB-TAC1']
    session_dict['ENB-TAC-NBIOT'] = b'\x00\x02'     
    session_dict['ENB-ID'] = random.randint(1, 9)
    session_dict['ENB-CELLID'] = random.randint(1000000,1900000)
    
    session_dict['NAS-KEY-EEA1'] = return_key(session_dict['KASME'],1,'NAS-ENC')
    session_dict['NAS-KEY-EEA2'] = return_key(session_dict['KASME'],2,'NAS-ENC')
    session_dict['NAS-KEY-EEA3'] = return_key(session_dict['KASME'],3,'NAS-ENC')
    session_dict['NAS-KEY-EIA1'] = return_key(session_dict['KASME'],1,'NAS-INT')
    session_dict['NAS-KEY-EIA2'] = return_key(session_dict['KASME'],2,'NAS-INT')
    session_dict['NAS-KEY-EIA3'] = return_key(session_dict['KASME'],3,'NAS-INT')  
    

    
    session_dict['UP-COUNT'] = -1    
    session_dict['DOWN-COUNT'] = -1
  
    session_dict['ENC-ALG'] = 0
    session_dict['INT-ALG'] = 0 
    session_dict['ENC-KEY'] = None
    session_dict['INT-KEY'] = None  
    session_dict['APN'] = APN
    
    
    session_dict['NAS-SMS-MT'] = None
    
    if session_dict['LOCAL_KEYS'] == True:
        if session_dict['IMSI'] == None:
            session_dict['IMSI'] = IMSI
        
    else:
        if session_dict['IMSI'] == None:
            try:
                session_dict['IMSI'] = return_imsi(session_dict['SERIAL-INTERFACE'])
                if session_dict['IMSI'] == None:
                    session_dict['LOCAL_KEYS'] = True
                    session_dict['IMSI'] = IMSI                
            except:
                if session_dict['LOCAL_MILENAGE'] == False:
                    session_dict['LOCAL_KEYS'] = True
                session_dict['IMSI'] = IMSI
        
    if session_dict['IMEISV'] == None:
        session_dict['IMEISV'] = IMEISV
    
    session_dict['ENCODED-IMSI'] = eNAS.encode_imsi(session_dict['IMSI'])
    session_dict['ENCODED-IMEI'] = eNAS.encode_imei(IMEISV)
    session_dict['ENCODED-GUTI'] = eNAS.encode_guti(int(session_dict['PLMN']),32769,1,12345678)
    
    session_dict['S-TMSI'] = None
    
    session_dict['TMSI'] = None
    session_dict['LAI'] = None
    
    session_dict['CPSR-TYPE'] = 0
    
    session_dict['S1-TYPE'] = "4G"
    session_dict['MOBILE-IDENTITY-TYPE'] = "IMSI" 
    session_dict['SESSION-SESSION-TYPE'] = "NONE"
    session_dict['SESSION-TYPE'] = "4G"
    session_dict['SESSION-TYPE-TUN'] = 1
    session_dict['PDP-TYPE'] = 1
    session_dict['ATTACH-PDN'] = None
    session_dict['ATTACH-TYPE'] = 1
    session_dict['TAU-TYPE'] = 0
    session_dict['SMS-UPDATE-TYPE'] = False
    session_dict['NBIOT-SESSION-TYPE'] = "NONE"
    session_dict['CPSR-TYPE'] = 0

    session_dict['UECONTEXTRELEASE-CSFB'] = False
    
    session_dict['PROCESS-PAGING'] = True
    session_dict['PCSCF-RESTORATION'] = False

    session_dict['NAS-KEY-SET-IDENTIFIER'] = 0
    
    session_dict['LOG'] = []

    session_dict['NON-IP-PACKET'] = 1
    session_dict['NON-IP-PACKETS'] = [NON_IP_PACKET_1, NON_IP_PACKET_2, NON_IP_PACKET_3, NON_IP_PACKET_4]

    return session_dict


def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]
    
def bytes2hex(byteArray):           
    return ''.join(hex(i).replace("0x", "0x0")[-2:] for i in byteArray)

def hex2bytes(hex_str):
    return bytearray.fromhex(hex_str)
 
def bcd(chars):  
    bcd_string = ""
    for i in range(len(chars) // 2):
        bcd_string += chars[1+2*i] + chars[2*i]
    bcd_bytes = bytes(bytearray.fromhex(bcd_string))
    return bcd_bytes

def return_plmn_s1ap(mccmnc):
    mccmnc = str(mccmnc)
    #print("Returning PLMN from: " + str(mccmnc))
    if len(mccmnc)==5:
        return bcd(mccmnc[0] + mccmnc[1] + mccmnc[2] + 'f' + mccmnc[3] + mccmnc[4]) 
    elif len(mccmnc)==6:
        return bcd(mccmnc[0] + mccmnc[1] + mccmnc[2] + mccmnc[3] + mccmnc[4] + mccmnc[5])

    else:
        return b''

def return_plmn(mccmnc):
    mccmnc = str(mccmnc)
    #print("Returning PLMN from: " + str(mccmnc))
    if len(mccmnc)==5:
        return bcd(mccmnc[0] + mccmnc[1] + mccmnc[2] + 'f' + mccmnc[3] + mccmnc[4]) 
    elif len(mccmnc)==6:
        return bcd(mccmnc[0] + mccmnc[1] + mccmnc[2] + mccmnc[5] + mccmnc[3] + mccmnc[4])

    else:
        return b''

def return_apn(apn):
    apn_bytes = bytes()
    apn_l = apn.split(".") 
    for word in apn_l:
        apn_bytes += struct.pack("!B", len(word)) + word.encode()     
    return apn_bytes    
    
def set_stream(client, stream):    
    sctp_default_send_param = bytearray(client.getsockopt(132,10,32))
    sctp_default_send_param[0]= stream
    client.setsockopt(132, 10, sctp_default_send_param)    
    return client
    
    
def return_key(kasme, algo, type): # 33.401 Annex A.7
    if type == 'NAS-ENC':
        type = '01'
    elif type == 'NAS-INT':
        type = '02'
        
    algo = '0'+str(algo)

    key = kasme
    message = unhexlify('15'+type+'0001'+algo+'0001')
    h = HMAC.new(key, msg=message, digestmod=SHA256)
    return h.digest()[-16:]


def return_kasme(plmn, autn, ck, ik):
    key = unhexlify(ck + ik)
    sqn_xor_ak = autn[0:12]
     
    message = unhexlify('10') + return_plmn(plmn) + unhexlify('0003' + sqn_xor_ak + '0006')
    h = HMAC.new(key, msg=message, digestmod=SHA256)
    return h.digest()[-32:]


def set_key(dic):
    if dic['INT-ALG'] == 0:
        dic['INT-KEY'] = None
    elif dic['INT-ALG'] == 1:
        dic['INT-KEY'] = dic['NAS-KEY-EIA1']
    elif dic['INT-ALG'] == 2:
        dic['INT-KEY'] = dic['NAS-KEY-EIA2']
    elif dic['INT-ALG'] == 3:
        dic['INT-KEY'] = dic['NAS-KEY-EIA3'] 
    if dic['ENC-ALG'] == 0:
        dic['ENC-KEY'] = None
    elif dic['ENC-ALG'] == 1:
        dic['ENC-KEY'] = dic['NAS-KEY-EEA1']
    elif dic['ENC-ALG'] == 2:
        dic['ENC-KEY'] = dic['NAS-KEY-EEA2']
    elif dic['ENC-ALG'] == 3:
        dic['ENC-KEY'] = dic['NAS-KEY-EEA3']         
    return dic

def nas_hash(dic):
    if dic['DIR'] == 0:
        return nas_hash_func(dic['NAS-ENC'], dic['UP-COUNT'], dic['DIR'], dic['INT-KEY'], dic['INT-ALG'])
    else:
        return nas_hash_func(dic['NAS-ENC'], dic['DOWN-COUNT'], dic['DIR'], dic['INT-KEY'], dic['INT-ALG'])

def nas_hash_func(nas, count, dir, key, algo):
    sqn=bytes([count%256]) #last byte
    if algo == 1:
        return EIA1(key, count, 0, dir, sqn+nas)
    elif algo ==2:
        return EIA2(key, count, 0, dir, sqn+nas)
    elif algo ==3:
        return EIA3(key, count, 0, dir, sqn+nas)
    else:
        return b'\x00\x00\x00\x00'

def nas_hash_service_request(dic):
    if dic['DIR'] == 0:
        return nas_hash_service_request_func(dic['NAS-ENC'], dic['UP-COUNT'], dic['DIR'], dic['INT-KEY'], dic['INT-ALG'])
    else:
        return nas_hash_service_request_func(dic['NAS-ENC'], dic['DOWN-COUNT'], dic['DIR'], dic['INT-KEY'], dic['INT-ALG'])

def nas_hash_service_request_func(nas, count, dir, key, algo):

    if algo == 1:
        return EIA1(key, count, 0, dir, nas)
    elif algo ==2:
        return EIA2(key, count, 0, dir, nas)
    elif algo ==3:
        return EIA3(key, count, 0, dir, nas)
    else:
        return b'\x00\x00\x00\x00'

    
def nas_encrypt(dic):
    if dic['DIR'] == 0:
        return nas_encrypt_func(dic['NAS-ENC'], dic['UP-COUNT'], dic['DIR'], dic['ENC-KEY'], dic['ENC-ALG'])
    else:
        return nas_encrypt_func(dic['NAS-ENC'], dic['DOWN-COUNT'], dic['DIR'], dic['ENC-KEY'], dic['ENC-ALG'])
        
def nas_encrypt_func(nas, count, dir, key, algo):
    if algo == 1:
        return EEA1(key, count, 0, dir, nas)
    elif algo ==2:
        return EEA2(key, count, 0, dir, nas)
    elif algo ==3:
        return EEA3(key, count, 0, dir, nas)
    else:
        return nas


def get_default_gateway_linux():
    """Read the default gateway directly from /proc."""
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                continue

            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16))), fields[0]
            


#abstraction functions
def milenage_res_ck_ik(ki, op, opc, rand):
    rand = unhexlify(rand)
    if op == None: 
        op = 16*b'\x00' #dummy since we will set opc directly
        m = Milenage(op)
        m.set_opc(opc)
    else:
        m = Milenage(op)
    res, ck, ik, ak = m.f2345(ki, rand)
    return hexlify(res), hexlify(ck), hexlify(ik)

def return_imsi(serial_interface_or_reader_index):
    try:
        return read_imsi_2(serial_interface_or_reader_index)
    except:
        try:
            return read_imsi(serial_interface_or_reader_index)
        except:
            try:
                return get_imsi(serial_interface_or_reader_index)
            except:
                try:
                    return https_imsi(serial_interface_or_reader_index)
                except:
                    return None
        
def return_res_ck_ik(serial_interface_or_reader_index, rand, autn):
    try:
        return read_res_ck_ik_2(serial_interface_or_reader_index, rand, autn)
    except:
        try:
            return read_res_ck_ik(serial_interface_or_reader_index, rand, autn)
        except:
            try:        
                return get_res_ck_ik(serial_interface_or_reader_index, rand, autn)
            except:
                try:
                    return https_res_ck_ik(serial_interface_or_reader_index, rand, autn)
                except:
                    return None, None, None



def get_imsi(serial_interface):

    imsi = None
    
    ser = serial.Serial(serial_interface,38400, timeout=0.5,xonxoff=True, rtscts=True, dsrdtr=True, exclusive =True)

    CLI = []
    CLI.append('AT+CIMI\r\n')
    
    a = time.time()
    for i in range(len(CLI)):
        ser.write(CLI[i].encode())
        buffer = ''

        while "OK\r\n" not in buffer and "ERROR\r\n" not in buffer:
            buffer +=  ser.read().decode("utf-8")
            
            if time.time()-a > 0.5:
                ser.write(CLI[i].encode())
                a = time.time() +1
            
        if i==0:    
            for m in buffer.split('\r\n'):
                if len(m) == 15:
                    imsi = m
         
    ser.close()
    return imsi


def get_res_ck_ik(serial_interface, rand, autn):
    res = None
    ck = None
    ik = None
    
    ser = serial.Serial(serial_interface,38400, timeout=0.5,xonxoff=True, rtscts=True, dsrdtr=True, exclusive =True)

    CLI = []
   
    #CLI.append('AT+CRSM=178,12032,1,4,0\r\n')
    CLI.append('AT+CSIM=14,"00A40000023F00"\r\n')
    CLI.append('AT+CSIM=14,"00A40000022F00"\r\n')
    CLI.append('AT+CSIM=42,"00A4040010A0000000871002FFFFFFFF8903050001"\r\n')
    CLI.append('AT+CSIM=78,\"008800812210' + rand.upper() + '10' + autn.upper() + '\"\r\n')

    a = time.time()
    for i in CLI:
        ser.write(i.encode())
        buffer = ''
    
        while "OK" not in buffer and "ERROR" not in buffer:
            buffer +=  ser.read().decode("utf-8")
        
            if time.time()-a > 0.5:
                ser.write(i.encode())

                a = time.time() + 1
                
    for i in buffer.split('"'):
        if len(i)==4:
            if i[0:2] == '61':
                len_result = i[-2:]
    
    LAST_CLI = 'AT+CSIM=10,"00C00000' + len_result + '\"\r\n'
    ser.write(LAST_CLI.encode())
    buffer = ''
    
    while "OK\r\n" not in buffer and "ERROR\r\n" not in buffer:
        buffer +=  ser.read().decode("utf-8")
        
    for result in buffer.split('"'):
        if len(result) > 10:
        

            res = result[4:20]
            ck = result[22:54]
            ik = result[56:88]
    
    ser.close()    
    return res, ck, ik
    

#reader functions
def bcd_str(chars):
    bcd_string = ""
    for i in range(len(chars) // 2):
        bcd_string += chars[1+2*i] + chars[2*i]
    return bcd_string

def read_imsi(reader_index):
    imsi = None
    r = readers()
    connection = r[int(reader_index)].createConnection()
    connection.connect()
    data, sw1, sw2 = connection.transmit(toBytes('00A40000023F00'))     
    data, sw1, sw2 = connection.transmit(toBytes('00A40000027F20'))
    data, sw1, sw2 = connection.transmit(toBytes('00A40000026F07'))
    data, sw1, sw2 = connection.transmit(toBytes('00B0000009'))  
    result = toHexString(data).replace(" ","")
    imsi = bcd_str(result)[-15:]
    
    return imsi

def read_res_ck_ik(reader_index, rand, autn):
    res = None
    ck = None
    ik = None
    r = readers()
    connection = r[int(reader_index)].createConnection()
    connection.connect()
    data, sw1, sw2 = connection.transmit(toBytes('00A40000023F00'))    
    data, sw1, sw2 = connection.transmit(toBytes('00A40000022F00')) 
    data, sw1, sw2 = connection.transmit(toBytes('00A4040010A0000000871002FFFFFFFF8903050001'))   
    data, sw1, sw2 = connection.transmit(toBytes('008800812210' + rand.upper() + '10' + autn.upper()))   
    if sw1 == 97:
        data, sw1, sw2 = connection.transmit(toBytes('00C00000') + [sw2])         
        result = toHexString(data).replace(" ", "")
        res = result[4:20]
        ck = result[22:54]
        ik = result[56:88]          

    return res, ck, ik


#reader functions - more generic using card module
def read_imsi_2(reader_index): #prepared for AUTS
    a = USIM(int(reader_index))
    return a.get_imsi()
    
def read_res_ck_ik_2(reader_index,rand,autn):
    a = USIM(int(reader_index))
    x = a.authenticate(RAND=toBytes(rand), AUTN=toBytes(autn))
    if len(x) == 1: #AUTS goes in RES position
        return toHexString(x[0]).replace(" ", ""), None, None
    elif len(x) > 2:
        return toHexString(x[0]).replace(" ", ""),toHexString(x[1]).replace(" ", ""),toHexString(x[2]).replace(" ", "") 
    else:
        return None, None, None



#https functions
def https_imsi(server):
    r = requests.get('https://' + server + '/?type=imsi', verify=False)
    return r.json()['imsi']

def https_res_ck_ik(server, rand, autn):
    r = requests.get('https://' + server + '/?type=rand-autn&rand=' + rand + '&autn=' + autn, verify=False)
    return r.json()['res'], r.json()['ck'], r.json()['ik']


    
    
######################################################################################################################################         
######################################################################################################################################

#------------------------------------------------------------------------------------------------------------------------------------#

######################################################################################################################################
#                                                    NON UE RELATED PROCEDURES:                                                      #
######################################################################################################################################

def S1SetupRequest(dic):

    IEs = []
    IEs.append({'id': 59, 'value': ('Global-ENB-ID', {'pLMNidentity': dic['ENB-PLMN'], 'eNB-ID' : ('macroENB-ID', (dic['ENB-ID'], 20))}), 'criticality': 'reject'})
    IEs.append({'id': 60, 'value': ('ENBname', dic['ENB-NAME']), 'criticality': 'ignore'})    
    if dic['S1-TYPE'] == "4G" :
        IEs.append({'id': 64, 'value': ('SupportedTAs', [{'tAC': dic['ENB-TAC1'], 'broadcastPLMNs': [dic['ENB-PLMN']]}, {'tAC': dic['ENB-TAC2'], 'broadcastPLMNs': [dic['ENB-PLMN']]}]), 'criticality': 'reject'})    
    elif dic['S1-TYPE'] == "NBIOT":
        IEs.append({'id': 64, 'value': ('SupportedTAs', [{'tAC': dic['ENB-TAC-NBIOT'], 'broadcastPLMNs': [dic['ENB-PLMN']], 'iE-Extensions': [{'id':232, 'criticality': 'reject', 'extensionValue':('RAT-Type','nbiot')}]}]), 'criticality': 'reject'})        
    elif dic['S1-TYPE'] == "BOTH":
        IEs.append({'id': 64, 'value': ('SupportedTAs', [{'tAC': dic['ENB-TAC'], 'broadcastPLMNs': [dic['ENB-PLMN']]}, {'tAC': dic['ENB-TAC-NBIOT'], 'broadcastPLMNs': [dic['ENB-PLMN']], 'iE-Extensions': [{'id':232, 'criticality': 'reject', 'extensionValue':('RAT-Type','nbiot')}]}]), 'criticality': 'reject'})        
    IEs.append({'id': 137, 'value': ('PagingDRX', 'v128'), 'criticality': 'ignore'})
    if dic['S1-TYPE'] == "NBIOT" or dic['S1-TYPE'] == "BOTH":
        IEs.append({'id': 234, 'value': ('NB-IoT-DefaultPagingDRX', 'v256'), 'criticality': 'ignore'})  
    val = ('initiatingMessage', {'procedureCode': 17, 'value': ('S1SetupRequest', {'protocolIEs': IEs}), 'criticality': 'ignore'})
    dic = eMENU.print_log(dic, "S1AP: sending S1SetupRequest")
    return val



def S1SetupResponseProcessing(IEs, dic):
    mme_name = ''
    servedPLMNs = b''
    servedGroupIDs = b''
    servedMMECs = b''
    RelativeMMECapacity = 0
    
    for i in IEs:
        if i['id'] == 61:
            mme_name = i['value'][1]
        elif i['id'] == 105:
            servedPLMNs = i['value'][1][0]['servedPLMNs'][0]
            servedGroupIDs = i['value'][1][0]['servedGroupIDs'][0]
            servedMMECs = i['value'][1][0]['servedMMECs'][0]
        elif i['id'] == 87:
            RelativeMMECapacity = i['value'][1]
            
    dic['MME-NAME'] = mme_name
    dic['MME-PLMN'] = servedPLMNs
    dic['MME-GROUP-ID'] = servedGroupIDs
    dic['MME-CODE'] = servedMMECs
    dic['MME-RELATIVE-CAPACITY'] = RelativeMMECapacity
    
    dic['STATE'] = 1
    return dic
    
    # improve when MME supports more than on network



def MMEConfigurationUpdateAcknowledge(IEs, dic):
    for i in IEs:
        if i['id'] == 61:
            mme_name = i['value'][1]
            dic['MME-NAME'] = mme_name
        elif i['id'] == 105:
            servedPLMNs = i['value'][1][0]['servedPLMNs']
            servedGroupIDs = i['value'][1][0]['servedGroupIDs']
            servedMMECs = i['value'][1][0]['servedMMECs']
            dic['MME-PLMN'] = servedPLMNs
            dic['MME-GROUP-ID'] = servedGroupIDs
            dic['MME-CODE'] = servedMMECs
        elif i['id'] == 87:
            RelativeMMECapacity = i['value'][1]
            dic['MME-RELATIVE-CAPACITY'] = RelativeMMECapacity

    answer = ('successfulOutcome', {'procedureCode': 30, 'value': ('MMEConfigurationUpdateAcknowledge', {'protocolIEs': []}), 'criticality': 'ignore'})
    dic = eMENU.print_log(dic, "S1AP: sending MMEConfigurationUpdateAcknowledge")
    return answer, dic


def Reset(dic):

    #assumes only one session so no need to check MME-UE-S1AP-ID and ENB-UE-S1AP-ID
    IEs = []
    IEs.append({'id': 2, 'value': ('Cause', ('misc', 'om-intervention')), 'criticality': 'ignore'})
    IEs.append({'id': 92, 'value': ('ResetType', ('s1-Interface', 'reset-all')), 'criticality': 'ignore'})
    
    val = ('initiatingMessage', {'procedureCode': 14, 'value': ('Reset', {'protocolIEs': IEs}), 'criticality': 'ignore'})
    dic = eMENU.print_log(dic, "S1AP: sending Reset")
    return val
    
######################################################################################################################################
######################################################################################################################################

#------------------------------------------------------------------------------------------------------------------------------------#

######################################################################################################################################
#                                                    UE RELATED PROCEDURES:                                                      #
######################################################################################################################################

###############
#   NAS Msg   #
###############
def nas_pco(pdp_type,pcscf_restoration):

    if pdp_type == 1:
        len_pco = struct.pack("!H", 32)
        if pcscf_restoration == False:
            return b'\x80\x80\x21\x1c\x01\x00\x00\x1c\x81\x06\x00\x00\x00\x00\x82\x06\x00\x00\x00\x00\x83\x06\x00\x00\x00\x00\x84\x06\x00\x00\x00\x00\x00\x0c\x00\x00\x0e\x00'        
        else:
            return b'\x80\x80\x21\x1c\x01\x00\x00\x1c\x81\x06\x00\x00\x00\x00\x82\x06\x00\x00\x00\x00\x83\x06\x00\x00\x00\x00\x84\x06\x00\x00\x00\x00\x00\x0c\x00\x00\x12\x00\x00\x0e\x00' 
    elif pdp_type == 2:
        len_pco = struct.pack("!H", 4)
        if pcscf_restoration == False:
            return b'\x80\x00\x03\x00\x00\x01\x00\x00\x0e\x00'
        else:
            return b'\x80\x00\x03\x00\x00\x01\x00\x00\x12\x00\x00\x0e\x00'
    elif pdp_type == 3:
        len_pco = struct.pack("!H", 33)
        if pcscf_restoration == False:
            return b'\x80\x80\x21\x1c\x01\x00\x00\x1c\x81\x06\x00\x00\x00\x00\x82\x06\x00\x00\x00\x00\x83\x06\x00\x00\x00\x00\x84\x06\x00\x00\x00\x00\x00\x03\x00\x00\x0c\x00\x00\x01\x00\x00\x0e\x00'
        else:
            return b'\x80\x80\x21\x1c\x01\x00\x00\x1c\x81\x06\x00\x00\x00\x00\x82\x06\x00\x00\x00\x00\x83\x06\x00\x00\x00\x00\x84\x06\x00\x00\x00\x00\x00\x03\x00\x00\x0c\x00\x00\x01\x00\x00\x12\x00\x00\x0e\x00'
     
#-------------------------------------------------------------------#
### ESM ### :
def nas_pdn_connectivity(eps_bearer_identity, pti, pdp_type, apn, pco, esm_information_transfer_flag, request_type=1):
    esm_list = []
    esm_list.append((2,eps_bearer_identity))   # protocol discriminator / eps bearer identity
    esm_list.append((0,'V',bytes([pti]))) # procedure trnasaction identity
    esm_list.append((0,'V',bytes([208]))) # message type: pdn connectivity request
    esm_list.append((0,'V',bytes([(pdp_type<<4) + request_type])))

    if esm_information_transfer_flag != None:
        esm_list.append((0xD,'TV',esm_information_transfer_flag)) 
    if apn != None:
        esm_list.append((0x28,'TLV',apn)) 
    if pco != None:
        esm_list.append((0x27,'TLV',pco)) 

    return eNAS.nas_encode(esm_list)    

def nas_pdn_disconnect(eps_bearer_identity, pti, linked_eps_bearer_id, pco):
    esm_list = []
    esm_list.append((2,eps_bearer_identity))   # protocol discriminator / eps bearer identity
    esm_list.append((0,'V',bytes([pti]))) # procedure trnasaction identity
    esm_list.append((0,'V',bytes([210]))) # message type: pdn disconnectrequest
    esm_list.append((0,'V',bytes([linked_eps_bearer_id]))) # pdn type / request type (ipv4, initial request)

    if pco != None:
        esm_list.append((0x27,'TLV',pco)) 

    return eNAS.nas_encode(esm_list)  


def nas_activate_default_eps_bearer_context_accept(eps_bearer_identity, pco):
    esm_list = []
    pti = 0
    esm_list.append((2,eps_bearer_identity))   # protocol discriminator / eps bearer identity
    esm_list.append((0,'V',bytes([pti]))) # procedure trnasaction identity
    esm_list.append((0,'V',bytes([194]))) # message type: activate_default_eps_bearer_context_accept
    if pco != None:
        esm_list.append((0x27,'TLV',pco))
    return eNAS.nas_encode(esm_list)  


def nas_activate_dedicated_eps_bearer_context_accept(eps_bearer_identity, pco):
    esm_list = []
    pti = 0
    esm_list.append((2,eps_bearer_identity))   # protocol discriminator / eps bearer identity
    esm_list.append((0,'V',bytes([pti]))) # procedure trnasaction identity
    esm_list.append((0,'V',bytes([198]))) # message type: activate_dedicated_eps_bearer_context_accept
    if pco != None:
        esm_list.append((0x27,'TLV',pco)) 
    return eNAS.nas_encode(esm_list)


def nas_modify_eps_bearer_context_accept(eps_bearer_identity, pco):
    esm_list = []
    pti = 0
    esm_list.append((2,eps_bearer_identity))   # protocol discriminator / eps bearer identity
    esm_list.append((0,'V',bytes([pti]))) # procedure trnasaction identity
    esm_list.append((0,'V',bytes([202]))) # message type: activate_dedicated_eps_bearer_context_accept
    if pco != None:
        esm_list.append((0x27,'TLV',pco)) 
    return eNAS.nas_encode(esm_list)




def nas_esm_information_response(eps_bearer_identity, pti, apn, pco):
    esm_list = []
    esm_list.append((2,eps_bearer_identity))   # protocol discriminator / eps bearer identity
    esm_list.append((0,'V',bytes([pti]))) # procedure trnasaction identity
    esm_list.append((0,'V',bytes([218]))) # message type: eesm information response
    if apn != None:
        esm_list.append((0x28,'TLV',apn)) 
    if pco != None:
        esm_list.append((0x27,'TLV',pco)) 
    return eNAS.nas_encode(esm_list) 


def nas_deactivate_eps_bearer_context_accept(eps_bearer_identity, pti, pco):
    esm_list = []
    esm_list.append((2,eps_bearer_identity))   # protocol discriminator / eps bearer identity
    esm_list.append((0,'V',bytes([pti]))) # procedure trnasaction identity
    esm_list.append((0,'V',bytes([206]))) # message type: deactivate eps bearer context accept
    if pco != None:
        esm_list.append((0x27,'TLV',pco)) 
    return eNAS.nas_encode(esm_list) 
    
    
    
def nas_esm_data_transport(eps_bearer_identity, pti, user_data_container):
    esm_list = []
    esm_list.append((2,eps_bearer_identity))   # protocol discriminator / eps bearer identity
    esm_list.append((0,'V',bytes([pti]))) # procedure trnasaction identity
    esm_list.append((0,'V',bytes([235]))) # message type: esm data transport
    esm_list.append((0,'LV-E',user_data_container)) 
    
    return eNAS.nas_encode(esm_list)     
    
    
    

#-------------------------------------------------------------#
### EMM ### :
def nas_attach_request(type, esm_information_transfer_flag, eps_identity, pdp_type, attach_type, tmsi, lai, sms_update, pcscf_restoration, ksi=0):
    emm_list = []
    emm_list.append((7,0))  # protocol discriminator / 
    emm_list.append((0,'V',bytes([65]))) # message type: attach request
    emm_list.append((0,'V',bytes([(ksi<<4)  + attach_type])))    # eps attach type/ nas key set identifier (EPS Attach /Keyset 0)    
    emm_list.append((0,'LV',eps_identity))  # eps mobile identity (imsi/odd number:9) + imsi. all in bcd)
    if type[0] == "4G":
        emm_list.append((0,'LV',unhexlify('f0f0c04009')))
    elif type[0] == "NBIOT":
        emm_list.append((0,'LV',unhexlify('f0f0000008a4')))
    elif type[0] == "5G":
        emm_list.append((0,'LV',unhexlify('f0f0c0c0000010')))

    pco = nas_pco(pdp_type,pcscf_restoration)
    if attach_type == 6: #EPS Emergency Attach
        emm_list.append((0,'LV-E',nas_pdn_connectivity(0,1,pdp_type,None,pco,esm_information_transfer_flag,4)))    
    else:
        emm_list.append((0,'LV-E',nas_pdn_connectivity(0,1,pdp_type,None,pco,esm_information_transfer_flag)))
    
    if type[0] == "4G":
        if attach_type == 2 and lai != None:
            emm_list.append((0x13, 'TV', lai))
        if attach_type == 2 and tmsi == None:
            emm_list.append((0x9, 'TV', 0))     
        
        if sms_update == True:
            emm_list.append((0xF, 'TV', 1))
        emm_list.append((0xC, 'TV', 1))
        
        if attach_type == 2 and tmsi != None:
            emm_list.append((0x10, 'TLV', tmsi[-3:-2] + bytes([(tmsi[-2]//64)*64])))    

        if type[1] == "PSM" or type[1] == "BOTH":
            emm_list.append((0x6A, 'TLV', b'\x0f')) # 15*2=30 sec.
            emm_list.append((0x5E, 'TLV', b'\x41'))
        if type[1] == "EDRX" or type[1] == "BOTH":
            emm_list.append((0x6E, 'TLV', b'\x75'))            
                
    elif type[0] == "NBIOT":
        if attach_type == 2 and lai != None:
            emm_list.append((0x13, 'TV', lai))
        if attach_type == 2 and tmsi == None:
            emm_list.append((0x9, 'TV', 0))  
        if sms_update == True:
            emm_list.append((0xF, 'TV', 5))
        else:
            emm_list.append((0xF, 'TV', 4))
        emm_list.append((0xC, 'TV', 1))

        if attach_type == 2 and tmsi != None:
            emm_list.append((0x10, 'TLV', tmsi[-3:-2] + bytes([(tmsi[-2]//64)*64]))) 
            
        if type[1] == "PSM" or type[1] == "BOTH":
            emm_list.append((0x6A, 'TLV', b'\x0f')) # 15*2=30 sec.
            emm_list.append((0x5E, 'TLV', b'\x41'))
        if type[1] == "EDRX" or type[1] == "BOTH":
            emm_list.append((0x6E, 'TLV', b'\x75'))
        
    elif type[0] == "5G":
        if attach_type == 2 and lai != None:
            emm_list.append((0x13, 'TV', lai))
        if attach_type == 2 and tmsi == None:
            emm_list.append((0x9, 'TV', 0)) 
        if sms_update == True:
            emm_list.append((0xF, 'TV', 1))
        if attach_type == 2 and tmsi != None:
            emm_list.append((0x10, 'TLV', tmsi[-3:-2] + bytes([(tmsi[-2]//64)*64])))             
        emm_list.append((0x6F, 'TLV', b'\xf0\x00\xf0\x00'))
    
    
    return eNAS.nas_encode(emm_list)




def nas_tracking_area_update_request(ksi, eps_update_type, eps_identity, type, tmsi, lai, sms_update):
    emm_list = []
    emm_list.append((7,0))  # protocol discriminator / 
    emm_list.append((0,'V',bytes([72]))) # message type: tracking area update request
    emm_list.append((0,'V',bytes([(ksi<<4) + eps_update_type])))   # ksi=6, update type: TA
    emm_list.append((0,'LV',eps_identity))  # eps mobile identity (imsi/odd number:9) + imsi. all in bcd)
    if type[0] == "4G":
        emm_list.append((0x58,'TLV',unhexlify('f0f0c04009')))
        if eps_update_type > 0 and lai != None:
            emm_list.append((0x13, 'TV', lai))
        if eps_update_type > 0 and tmsi == None:
            emm_list.append((0x9, 'TV', 0))
        if sms_update == True:
            emm_list.append((0xF, 'TV', 1))
        emm_list.append((0xC, 'TV', 1))
        if eps_update_type > 0 and tmsi != None:
            emm_list.append((0x10, 'TLV', tmsi[-3:-2] + bytes([(tmsi[-2]//64)*64])))   

        if type[1] == "PSM" or type[1] == "BOTH":
            emm_list.append((0x6A, 'TLV', b'\x05'))
            emm_list.append((0x5E, 'TLV', b'\x41'))
            
        if type[1] == "EDRX" or type[1] == "BOTH":
            emm_list.append((0x6E, 'TLV', b'\x75'))

            
    elif type[0] == "NBIOT":
        emm_list.append((0x58,'TLV',unhexlify('f0f0000008a4')))
    elif type[0] == "5G":
        emm_list.append((0x58,'TLV',unhexlify('f0f0c0c0000010')))
    
    if type[0] == "NBIOT":
        if eps_update_type > 0 and lai != None:
            emm_list.append((0x13, 'TV', lai))
        if eps_update_type > 0 and tmsi == None:
            emm_list.append((0x9, 'TV', 0))  
        if sms_update == True:
            emm_list.append((0xF, 'TV', 5))
        else:
            emm_list.append((0xF, 'TV', 4))
        emm_list.append((0xC, 'TV', 1))

        if eps_update_type > 0 and tmsi != None:
            emm_list.append((0x10, 'TLV', tmsi[-3:-2] + bytes([(tmsi[-2]//64)*64])))         
        
        if type[1] == "PSM" or type[1] == "BOTH":
            emm_list.append((0x6A, 'TLV', b'\x05'))
            emm_list.append((0x5E, 'TLV', b'\x41'))
        if type[1] == "EDRX" or type[1] == "BOTH":
            emm_list.append((0x6E, 'TLV', b'\x75'))

    elif type[0] == "5G":
        if eps_update_type > 0 and lai != None:
            emm_list.append((0x13, 'TV', lai))
        if eps_update_type > 0 and tmsi == None:
            emm_list.append((0x9, 'TV', 0))
        if sms_update == True:
            emm_list.append((0xF, 'TV', 1))            
        if eps_update_type > 0 and tmsi != None:
            emm_list.append((0x10, 'TLV', tmsi[-3:-2] + bytes([(tmsi[-2]//64)*64])))               
        emm_list.append((0x6F, 'TLV', b'\xf0\x00\xf0\x00'))

    return eNAS.nas_encode(emm_list)


def nas_extended_service_request(ksi, mobile_identity):
    emm_list = []
    emm_list.append((7,0))  # protocol discriminator / 
    emm_list.append((0,'V',bytes([76]))) # message type: extende service request
    emm_list.append((0,'V',bytes([(ksi<<4) + 1]))) #mobile terminating cs fallback
    emm_list.append((0,'LV',b'\xf4' + mobile_identity))
    emm_list.append((0xB,'TV',1))    
    return eNAS.nas_encode(emm_list)


def nas_detach_request(ksi, detach_type, eps_identity):
    emm_list = []
    emm_list.append((7,0))  # protocol discriminator / 
    emm_list.append((0,'V',bytes([69]))) # message type: detach request
    emm_list.append((0,'V',bytes([(ksi<<4) + detach_type])))   # ksi=6, update type: TA
    emm_list.append((0,'LV',eps_identity))  # eps mobile identity (imsi/odd number:9) + imsi. all in bcd)
    return eNAS.nas_encode(emm_list)


def nas_authentication_response(xres):
    emm_list = []
    emm_list.append((7,0))  # protocol discriminator / 
    emm_list.append((0,'V',bytes([83]))) # message type: authentication response
    emm_list.append((0,'LV',xres))
    return eNAS.nas_encode(emm_list)

def nas_nondelivery_Indication(rand,autn):
    emm_list = []
    emm_list.append((7,0))  # protocol discriminator / 
    emm_list.append((0,'V',bytes([82]))) # message type: authentication request
    emm_list.append((0,'V',rand))
    emm_list.append((0,'LV',autn))
    return eNAS.nas_encode(emm_list)


def nas_identity_response(imsi_or_imeisv):
    emm_list = []
    emm_list.append((7,0))  # protocol discriminator / 
    emm_list.append((0,'V',bytes([86]))) # message type: identity response
    emm_list.append((0,'LV',bcd(imsi_or_imeisv )))  # eps mobile identity (imsi/odd number:9) + imsi. all in bcd)
    return eNAS.nas_encode(emm_list)


def nas_security_mode_complete(imeisv):
    emm_list = []
    emm_list.append((7,0))  # protocol discriminator / 
    emm_list.append((0,'V',bytes([94]))) # message type: security mode complete
    if imeisv != None:
        emm_list.append((0x23,'TLV',bcd('3' + imeisv + 'f')))
    return eNAS.nas_encode(emm_list)

def nas_attach_complete(eps_bearer_identity):
    emm_list = []
    emm_list.append((7,0))  # protocol discriminator / 
    emm_list.append((0,'V',bytes([67]))) # message type: attach complete
    emm_list.append((0,'LV-E',nas_activate_default_eps_bearer_context_accept(eps_bearer_identity,None)))
    return eNAS.nas_encode(emm_list)


def nas_security_protected_nas_message(security_header,message_authentication_code, sequence_number, nas_message):
    emm_list = []
    emm_list.append((7,security_header))  # protocol discriminator / 
    emm_list.append((0,'V',message_authentication_code)) # message type: authentication response
    emm_list.append((0,'V',sequence_number))
    emm_list.append((0,'V',nas_message))
    return eNAS.nas_encode(emm_list)

def nas_service_request(security_header, ksi, sequence_number, message_authentication_code):
    emm_list = []
    emm_list.append((7,security_header))  # protocol discriminator / 
    emm_list.append((0,'V',bytes([((ksi<<5) & 0xff) + (sequence_number & 0x1f)]))) # message type: authentication response  
    emm_list.append((0,'V',message_authentication_code)) # message type: authentication response

    return eNAS.nas_encode(emm_list)

def nas_tracking_area_update_complete():
    emm_list = []
    emm_list.append((7,0))  # protocol discriminator / 
    emm_list.append((0,'V',bytes([74]))) # message type: tracking area update complete
    return eNAS.nas_encode(emm_list)

def nas_guti_reallocation_complete():
    emm_list = []
    emm_list.append((7,0))  # protocol discriminator / 
    emm_list.append((0,'V',bytes([81]))) # message type: guti reallocation complete
    return eNAS.nas_encode(emm_list)

def nas_detach_accept():
    emm_list = []
    emm_list.append((7,0))  # protocol discriminator / 
    emm_list.append((0,'V',bytes([70]))) # message type: detach accept
    return eNAS.nas_encode(emm_list)


def nas_control_plane_service_request(ksi,control_plane_service_type, esm_message_container,nas_message_container, eps_bearer_context_status):
    emm_list = []
    emm_list.append((7,0))  # protocol discriminator / 
    emm_list.append((0,'V',bytes([77]))) # message type: control plane service request
    emm_list.append((0,'V',bytes([((ksi<<4) & 0xf0) + (control_plane_service_type & 0x0f)]))) 
    if esm_message_container != None:
        emm_list.append((0x78,'TLV-E',esm_message_container))
    if nas_message_container != None:
        emm_list.append((0x67,'TLV',nas_message_container))
    if eps_bearer_context_status != None:
        emm_list.append((0x57,'TLV',eps_bearer_context_status))
        
    return eNAS.nas_encode(emm_list)    


def nas_uplink_nas_transport(sms):
    emm_list = []
    emm_list.append((7,0))  # protocol discriminator / 
    emm_list.append((0,'V',bytes([99]))) # message type: uplink_nas_transport
    emm_list.append((0,'LV',sms))    
    return eNAS.nas_encode(emm_list)



###############
# NAS Process #
###############
def ProcessUplinkNAS(message_type, dic):
    encrypted_flag = False
    if message_type == 'service request':
        dic['UP-COUNT'] += 1 
        dic['DIR'] = 0
        dic['NAS-ENC'] =  nas_service_request(12,dic['NAS-KEY-SET-IDENTIFIER'],dic['UP-COUNT']%256,b'\x00\x00')[0:2] #use first 2 bytes to calculate integrity 24.301 9.9.3.28
        mac_bytes = nas_hash_service_request(dic)
        dic['NAS'] = dic['NAS-ENC'] + mac_bytes[-2:]    
        dic = eMENU.print_log(dic, "NAS: sending ServiceRequest")

    elif message_type == 'extended service request':
        dic['NAS-ENC'] = nas_extended_service_request(dic['NAS-KEY-SET-IDENTIFIER'], dic['S-TMSI'][1:5])
        dic['UP-COUNT'] += 1 
        dic['DIR'] = 0
    
        mac_bytes = nas_hash(dic)
        dic['NAS'] = nas_security_protected_nas_message(1,mac_bytes,bytes([dic['UP-COUNT']%256]),dic['NAS-ENC']) 
        dic = eMENU.print_log(dic, "NAS: sending ExtendingServiceRequest")
        
        #ativates ue context release after initialsetuprequest by mme
        dic['UECONTEXTRELEASE-CSFB'] = True

    
    elif message_type == 'tracking area update request':
        dic['NAS-ENC'] = nas_tracking_area_update_request(dic['NAS-KEY-SET-IDENTIFIER'], dic['TAU-TYPE'], dic['GUTI'], (dic['SESSION-TYPE'], dic['SESSION-SESSION-TYPE']), dic['TMSI'], dic['LAI'], dic['SMS-UPDATE-TYPE'])
        dic['UP-COUNT'] += 1 
        dic['DIR'] = 0

        mac_bytes = nas_hash(dic)
        dic['NAS'] = nas_security_protected_nas_message(1,mac_bytes,bytes([dic['UP-COUNT']%256]),dic['NAS-ENC'])
        dic = eMENU.print_log(dic, "NAS: sending TrackingAreaUpdateRequest")
        
    elif message_type == 'tracking area update request periodic':
        dic['NAS-ENC'] = nas_tracking_area_update_request(dic['NAS-KEY-SET-IDENTIFIER'],3,dic['GUTI'], (dic['SESSION-TYPE'], dic['SESSION-SESSION-TYPE']), dic['TMSI'], dic['LAI'], dic['SMS-UPDATE-TYPE'])
        dic['UP-COUNT'] += 1 
        dic['DIR'] = 0

        mac_bytes = nas_hash(dic)
        dic['NAS'] = nas_security_protected_nas_message(1,mac_bytes,bytes([dic['UP-COUNT']%256]),dic['NAS-ENC']) 
        dic = eMENU.print_log(dic, "NAS: sending TrackingAreaUpdateRequest")

    elif message_type == 'detach request':
        dic['NAS-ENC'] = nas_detach_request(dic['NAS-KEY-SET-IDENTIFIER'],1,dic['GUTI']) # normal detach (0---). EPS detach (-001)
        dic['UP-COUNT'] += 1 
        dic['DIR'] = 0
        if dic['MME-UE-S1AP-ID'] > 0: #s1 up
            nas_encrypted = nas_encrypt(dic)
            dic['NAS-ENC'] = nas_encrypted 
        mac_bytes = nas_hash(dic)
        if dic['MME-UE-S1AP-ID'] > 0: #s1 up
            dic['NAS'] = nas_security_protected_nas_message(2,mac_bytes,bytes([dic['UP-COUNT']%256]),dic['NAS-ENC']) 
        else:
            dic['NAS'] = nas_security_protected_nas_message(1,mac_bytes,bytes([dic['UP-COUNT']%256]),dic['NAS-ENC']) #com s1 em baixo vai no initialuemessage so com integrity
        dic = eMENU.print_log(dic, "NAS: sending DetachRequest")   
    
    elif message_type == 'pdn connectivity request':
        pco = nas_pco(dic['PDP-TYPE'],dic['PCSCF-RESTORATION'])
        if dic['ATTACH-TYPE'] == 6: #If Attach Type = EPS Emergency PDN Connectity is with Emergency APN 
            dic['NAS-ENC'] = nas_pdn_connectivity(0, 2, dic['PDP-TYPE'],None, pco, None,4)        
        else:
            dic['NAS-ENC'] = nas_pdn_connectivity(0, 2, dic['PDP-TYPE'],eNAS.encode_apn(APN), pco, None)
        dic['UP-COUNT'] += 1 
        dic['DIR'] = 0
        nas_encrypted = nas_encrypt(dic)
        dic['NAS-ENC'] = nas_encrypted 
        mac_bytes = nas_hash(dic)
        dic['NAS'] = nas_security_protected_nas_message(2,mac_bytes,bytes([dic['UP-COUNT']%256]),dic['NAS-ENC']) 
        dic = eMENU.print_log(dic, "NAS: sending PDNConnectivityRequest") 

    elif message_type == 'pdn disconnect request':
        dic['NAS-ENC'] = nas_pdn_disconnect(0, 2, dic['EPS-BEARER-IDENTITY'][-1], None)
        dic['UP-COUNT'] += 1 
        dic['DIR'] = 0
        nas_encrypted = nas_encrypt(dic)
        dic['NAS-ENC'] = nas_encrypted 
        mac_bytes = nas_hash(dic)
        dic['NAS'] = nas_security_protected_nas_message(2,mac_bytes,bytes([dic['UP-COUNT']%256]),dic['NAS-ENC']) 
        dic = eMENU.print_log(dic, "NAS: sending PDNDisconnectRequest") 

    elif message_type == 'control plane service request':
        dic['NAS-ENC'] = nas_control_plane_service_request(dic['NAS-KEY-SET-IDENTIFIER'],dic['CPSR-TYPE'], None, None, None)
        dic['UP-COUNT'] += 1 
        dic['DIR'] = 0
        #nas_encrypted = nas_encrypt(dic)
        #dic['NAS-ENC'] = nas_encrypted 
        mac_bytes = nas_hash(dic)
        dic['NAS'] = nas_security_protected_nas_message(5,mac_bytes,bytes([dic['UP-COUNT']%256]),dic['NAS-ENC']) # 5 especifico para esta mensagem
        dic = eMENU.print_log(dic, "NAS: sending ControlPlaneServiceRequest") 

    elif message_type == 'control plane service request with esm message container':
        dic['NAS-ENC'] = nas_control_plane_service_request(dic['NAS-KEY-SET-IDENTIFIER'],dic['CPSR-TYPE'], dic['NAS-ENC'], None, b'\x20\x00')
        #dic['UP-COUNT'] += 1 - not needed becase SEQ was incremented when building the ESM Container
        dic['DIR'] = 0

        mac_bytes = nas_hash(dic)
        dic['NAS'] = nas_security_protected_nas_message(5,mac_bytes,bytes([dic['UP-COUNT']%256]),dic['NAS-ENC']) # 5 especifico para esta mensagem
        dic = eMENU.print_log(dic, "NAS: sending ControlPlaneServiceRequest")         
        
    elif message_type == 'esm data transport':
        dic['NAS-ENC'] = nas_esm_data_transport(dic['EPS-BEARER-IDENTITY'][-1],0,dic['USER-DATA-CONTAINER'])
        dic['UP-COUNT'] += 1 
        dic['DIR'] = 0
        nas_encrypted = nas_encrypt(dic)
        dic['NAS-ENC'] = nas_encrypted 
        mac_bytes = nas_hash(dic)
        dic['NAS'] = nas_security_protected_nas_message(2,mac_bytes,bytes([dic['UP-COUNT']%256]),dic['NAS-ENC']) #mudei de 4 para 2
        dic = eMENU.print_log(dic, "NAS: sending ESMDataTransport") 

    elif message_type == 'uplink nas transport': 
        SMS = b'\x19\x01\x3c\x00\x02\x00\x07\x91\x53\x91\x26\x01\x00\x00\x30\x01\x02\x0c\x91\x53\x91\x66\x78\x92\x30\x00\x00\x27\x45\xb7\x3d\x1d\x6e\xb5\xcb\xa0\x7a\x1b\x34\x6d\x4e\x41\x73\xb3\x19\x04\x0f\xcb\xc3\x20\x73\x58\x5f\x96\x83\xea\x6d\x10\xbd\x3c\xa7\x97\x01'    
        dic['NAS-ENC'] = nas_uplink_nas_transport(SMS)
        dic['UP-COUNT'] += 1 
        dic['DIR'] = 0
        nas_encrypted = nas_encrypt(dic)
        dic['NAS-ENC'] = nas_encrypted 
        mac_bytes = nas_hash(dic)
        dic['NAS'] = nas_security_protected_nas_message(2,mac_bytes,bytes([dic['UP-COUNT']%256]),dic['NAS-ENC']) #mudei de 4 para 2
        dic = eMENU.print_log(dic, "NAS: sending UplinkNASTransport")
        
    return dic

def ProcessDownlinkNAS(dic):
    if dic['NAS'] == None:
        #exit. Nothing to do
        return dic
        
    nas_list = eNAS.nas_decode(dic['NAS'])
    
    encrypted_flag = False
    new_eps_security_flag = False
    

    #if encrpyted, decoded, and the decoded becomes the new nas_list
    if nas_list[-1][0] == 'nas message encrypted':
        encrypted_flag = False
        
        dic['DOWN-COUNT'] += 1
        dic['NAS-ENC'] = nas_list[-1][1] 
        dic['DIR'] = 1
        if nas_list[1][0] == 'security header' and (nas_list[1][1] == 1 or nas_list[1][1] == 3):
            nas_decoded = dic['NAS-ENC']
            if nas_list[1][1] == 3:
                dic['DOWN-COUNT'] = 0
                new_eps_security_flag = True
        else:
            nas_decoded = nas_encrypt(dic)
        nas_list = eNAS.nas_decode(nas_decoded)
       
    
    if nas_list[0][1] == 7: message_type = nas_list[2][1]
    if nas_list[0][1] == 2: message_type = nas_list[3][1]
    
    if message_type == 82: # authentication request
        dic = eMENU.print_log(dic, "NAS: AuthenticatonRequest received")
        if dic['LOCAL_KEYS'] == True:
            dic['NAS'] = nas_authentication_response(dic['XRES'])
            if encrypted_flag == True:

                dic['NAS-ENC'] = dic['NAS'] 
                dic['UP-COUNT'] += 1 
                dic['DIR'] = 0
                nas_encrypted = nas_encrypt(dic)
                dic['NAS-ENC'] = nas_encrypted 
                mac_bytes = nas_hash(dic)
                dic['NAS'] = nas_security_protected_nas_message(2,mac_bytes,bytes([dic['UP-COUNT']%256]),dic['NAS-ENC']) #mudei de 4 para 2
     
            
        else:
            for i in nas_list:
                if i[0] == "rand":
                    rand_err=i[1]
                    rand = hexlify(i[1]).decode('utf-8')
                elif i[0] == "autn":
                    autn_error= i[1]
                    autn = hexlify(i[1]).decode('utf-8')
            
            if dic['LOCAL_MILENAGE'] == True:
                res, ck, ik = milenage_res_ck_ik(dic['KI'], dic['OP'], dic['OPC'], rand) #no sqn validation
            else:
                res, ck, ik = return_res_ck_ik(dic['SERIAL-INTERFACE'],rand, autn)
            if res is not None and ck is not None and ik is not None:
                dic['KASME'] = return_kasme(dic['PLMN'], autn, ck, ik)
                dic['XRES'] = unhexlify(res)
            elif res is not None and ck is not None and ik is None: #ck as kasme
                dic['KASME'] = unhexlify(ck)
                dic['XRES'] = unhexlify(res)        
            if dic['AUTH-ERROR']:
                dic['NAS']=nas_nondelivery_Indication(unhexlify("00"+rand),unhexlify(autn))
            else:
                dic['NAS'] = nas_authentication_response(dic['XRES'])

            if encrypted_flag == True:
                dic['NAS-ENC'] = dic['NAS'] 
                dic['UP-COUNT'] += 1 
                dic['DIR'] = 0
                nas_encrypted = nas_encrypt(dic)
                dic['NAS-ENC'] = nas_encrypted 
                mac_bytes = nas_hash(dic)
                dic['NAS'] = nas_security_protected_nas_message(2,mac_bytes,bytes([dic['UP-COUNT']%256]),dic['NAS-ENC']) #mudei de 4 para 2
         
            dic['NAS-KEY-EEA1'] = return_key(dic['KASME'],1,'NAS-ENC')
            dic['NAS-KEY-EEA2'] = return_key(dic['KASME'],2,'NAS-ENC')
            dic['NAS-KEY-EEA3'] = return_key(dic['KASME'],3,'NAS-ENC')
            dic['NAS-KEY-EIA1'] = return_key(dic['KASME'],1,'NAS-INT')
            dic['NAS-KEY-EIA2'] = return_key(dic['KASME'],2,'NAS-INT')
            dic['NAS-KEY-EIA3'] = return_key(dic['KASME'],3,'NAS-INT') 

     

    elif message_type == 84: # authentication reject
        dic = eMENU.print_log(dic, "NAS: AuthenticatonReject received")
        os.system(f"echo FAILED>/var/log/sim/ue_{dic['IMSI']}_status")
        dic['NAS'] = None
        dic['STATE'] = 1

    
    elif message_type == 93: #security mode
        if new_eps_security_flag == True:
            dic['UP-COUNT'] = -1    
            
        dic = eMENU.print_log(dic, "NAS: SecurityMode received")
        imeisv_request = None
        for i in nas_list:
            if i[0] == 'selected nas security algorithms':
                dic['INT-ALG'] = i[1]%16
                dic['ENC-ALG'] = i[1]//16
                dic = set_key(dic)

                
            elif i[0] == 'nas key set identifier':
                dic['NAS-KEY-SET-IDENTIFIER'] = i[1]
                
            elif i[0] == 'imeisv request':
                imeisv_request = dic['IMEISV']
        
        dic['NAS-ENC'] = nas_security_mode_complete(imeisv_request)

        
        dic['UP-COUNT'] += 1 
        dic['DIR'] = 0
        nas_encrypted = nas_encrypt(dic)
        dic['NAS-ENC'] = nas_encrypted 
        mac_bytes = nas_hash(dic)
        
        dic['NAS'] = nas_security_protected_nas_message(4,mac_bytes,bytes([dic['UP-COUNT']%256]),dic['NAS-ENC'])
        dic = eMENU.print_log(dic, "NAS: sending SecurityModeComplete")

    elif message_type == 66: #attach accept
        dic = eMENU.print_log(dic, "NAS: AttachAccept received")  
       
        for i in nas_list:
            if i[0] == 'esm message container':
                
                for m in i[1]:
      
                    if m[0] == 'eps bearer identity':
                        if m[1] not in dic['EPS-BEARER-IDENTITY']:
                            dic['EPS-BEARER-IDENTITY'].append(m[1])
                            dic['EPS-BEARER-STATE'].append(1)
                            dic['EPS-BEARER-TYPE'].append(0)
                            dic['PDN-ADDRESS'].append('')
                            dic['EPS-BEARER-APN'].append('')
                           
                        position = dic['EPS-BEARER-IDENTITY'].index(m[1])
                    elif m[0] == 'pdn address':
                        dic['PDN-ADDRESS'][position] = m[1]
                        pdn_address = eNAS.decode_pdn_address(dic['PDN-ADDRESS'][position])
                        dic = eMENU.print_log(dic, pdn_address)
                        #if dic['PDN-ADDRESS-IPV4'] is not None:                        
                        #    subprocess.call("ip addr del " + dic['PDN-ADDRESS-IPV4'] + "/32 dev tun" + str(dic['IMSI']), shell=True) 
                        dic['PDN-ADDRESS-IPV4'] = None
                        dic['PDN-ADDRESS-IPV6'] = None
                        
                        for x in pdn_address:
                            if x[0] == 'ipv4':
                                          
                                dic['PDN-ADDRESS-IPV4'] = x[1] 
                                dic['GTP-KEY']=socket.inet_aton(x[1])
                                dic['UE-NAMESPACE']=ue_eth_pair()
                                add_ns(dic['IMSI'],dic['UE-NAMESPACE'][0],dic['UE-NAMESPACE'][1],dic['PDN-ADDRESS-IPV4'])
                                #try:
                                #    tap = TunTap(nic_type="Tap",nic_name=f"tun{dic['IMSI']}")
                                #    dic['tap']=tap
                                #    tap.config(ip=x[1],mask="255.255.255.255",gateway="0.0.0.0")
                                #except:
                                #    pass
                                #subprocess.call("ip addr add " + x[1] + "/32 dev tun" + str(dic['SESSION-TYPE-TUN']), shell=True)
       
                            elif x[0] == 'ipv6':
                                 #operating system will process Router Advertisement
                                if dic['PDN-ADDRESS-IPV6'] is not None:                                  
                                    subprocess.call("ip -6 addr del " + dic['PDN-ADDRESS-IPV6'] + "/64 dev tun" + str(dic['SESSION-TYPE-TUN']), shell=True)
                                dic['PDN-ADDRESS-IPV6'] = x[1]                   
                                subprocess.call("ip -6 addr add " + x[1] + "/64 dev tun" + str(dic['SESSION-TYPE-TUN']), shell=True)
                            
                    elif m[0] == 'access point name':
                        
                        dic['EPS-BEARER-APN'][position] = m[1]
                        dic = eMENU.print_log(dic, eNAS.decode_apn(dic['EPS-BEARER-APN'][position]))
                        
            elif i[0] == 'guti':
                dic['GUTI'] = i[1]
                dic['S-TMSI'] = i[1][-5:]
                dic['ENCODED-GUTI'] = dic['GUTI']               
                dic = eMENU.print_log(dic, eNAS.decode_eps_mobile_identity(dic['GUTI'] ))
                
            elif i[0] == 'ms identity':
                dic['TMSI'] = i[1]
                dic = eMENU.print_log(dic, dic['TMSI'])
            elif i[0] == 'location area identification':
                dic['LAI'] = i[1]
                dic = eMENU.print_log(dic, dic['LAI'])
                
               
        dic['NAS-ENC'] = nas_attach_complete(dic['EPS-BEARER-IDENTITY'][position])
        dic['UP-COUNT'] += 1 
        dic['DIR'] = 0
        global gtp_dict
        gtp_dict[dic['GTP-KEY']] =((dic['SGW-TEID'])[-1],(dic['SGW-GTP-ADDRESS'])[-1])
        nas_encrypted = nas_encrypt(dic)
        dic['NAS-ENC'] = nas_encrypted 
        mac_bytes = nas_hash(dic)
        dic['NAS'] = nas_security_protected_nas_message(2,mac_bytes,bytes([dic['UP-COUNT']%256]),dic['NAS-ENC']) #mudei de 4 para 2
        dic = eMENU.print_log(dic, "NAS: sending AttachComplete")
        os.system(f"echo CONNECTED>/var/log/sim/ue_{dic['IMSI']}_status")
        dic['STATE'] = 2


    elif message_type == 68: #attach reject
        dic = eMENU.print_log(dic, "NAS: AttachReject received")
        os.system(f"echo FAILED>/var/log/sim/ue_{dic['IMSI']}_status")
        dic['NAS'] = None
        dic['STATE'] = 1
        
    elif message_type == 69: #detach request
    
        if len(dic['SGW-GTP-ADDRESS']) > 0:
            #os.write(dic['PIPE-OUT-GTPU-ENCAPSULATE'],b'\x02' + dic['SGW-GTP-ADDRESS'][-1] + dic['SGW-TEID'][-1])
            #os.write(dic['PIPE-OUT-GTPU-DECAPSULATE'],b'\x02' + dic['SGW-GTP-ADDRESS'][-1] + b'\x00\x00\x00' + bytes([dic['RAB-ID'][-1]]))
            dic = eMENU.print_log(dic, "GTP-U: Deactivation due to DetachRequest received")
        
        dic['RAB-ID'] = []
        dic['SGW-GTP-ADDRESS'] = []
        dic['SGW-TEID'] = []
        dic['EPS-BEARER-IDENTITY'] = []
        dic['EPS-BEARER-TYPE'] = []  # default 0, dedicated 1
        dic['EPS-BEARER-STATE']  = [] # active 1, inactive 0
        dic['EPS-BEARER-APN'] = []
        dic['PDN-ADDRESS'] = []      
        dic['STATE'] = 1
    
        dic = eMENU.print_log(dic, "NAS: DetachRequest received")
        dic = eMENU.print_log(dic, [nas_list[-1]])
        
        dic['NAS-ENC'] = nas_detach_accept()
        dic['UP-COUNT'] += 1 
        dic['DIR'] = 0
        nas_encrypted = nas_encrypt(dic)
        dic['NAS-ENC'] = nas_encrypted 
        mac_bytes = nas_hash(dic)
        dic['NAS'] = nas_security_protected_nas_message(2,mac_bytes,bytes([dic['UP-COUNT']%256]),dic['NAS-ENC']) #mudei de 4 para 2
        dic = eMENU.print_log(dic, "NAS: sending DetachAccept")

    elif message_type == 70: #detach accept
        if len(dic['SGW-GTP-ADDRESS']) > 0:
            #os.write(dic['PIPE-OUT-GTPU-ENCAPSULATE'],b'\x02' + dic['SGW-GTP-ADDRESS'][-1] + dic['SGW-TEID'][-1])
            #os.write(dic['PIPE-OUT-GTPU-DECAPSULATE'],b'\x02' + dic['SGW-GTP-ADDRESS'][-1] + b'\x00\x00\x00' + bytes([dic['RAB-ID'][-1]]))
            dic = eMENU.print_log(dic, "GTP-U: Deactivation due to DetachAccept received")
        
        dic = eMENU.print_log(dic, "NAS: DetachAccept received")
        dic['NAS'] = None
        dic['RAB-ID'] = []
        dic['SGW-GTP-ADDRESS'] = []
        dic['SGW-TEID'] = []
        dic['EPS-BEARER-IDENTITY'] = []
        dic['EPS-BEARER-TYPE'] = []  # default 0, dedicated 1
        dic['EPS-BEARER-STATE']  = [] # active 1, inactive 0
        dic['EPS-BEARER-APN'] = []
        dic['PDN-ADDRESS'] = []    
        dic['STATE'] = 1
        global user_dict
        if dic['IMSI'] in user_dict:
            del gtp_dict[dic['GTP-KEY']]
            del user_dict[dic['IMSI']]
            ue_eth_pair(dic['UE-NAMESPACE'])
            delete_ns(dic['IMSI'],dic['UE-NAMESPACE'][1])
            

    elif message_type == 73: #tracking area update accept
        dic = eMENU.print_log(dic, "NAS: TrackingAreaUpdateAccept received")
        dic['NAS'] = None #so envia tau complete se guti tiver mudado
        
        for i in nas_list:
            if i[0] == 'guti':
                dic = eMENU.print_log(dic, str(eNAS.decode_eps_mobile_identity(dic['GUTI'] )))
                if dic['GUTI'] != i[1] and dic['NAS'] == None: # new GUTI assigned
                    
                    dic['NAS-ENC'] = nas_tracking_area_update_complete()
                    dic['UP-COUNT'] += 1 
                    dic['DIR'] = 0
                    nas_encrypted = nas_encrypt(dic)
                    dic['NAS-ENC'] = nas_encrypted 
                    mac_bytes = nas_hash(dic)
                    dic['NAS'] = nas_security_protected_nas_message(2,mac_bytes,bytes([dic['UP-COUNT']%256]),dic['NAS-ENC']) #mudei de 4 para 2
                    dic = eMENU.print_log(dic, "NAS: sending trackingAreaUpdateComplete")
                dic['GUTI'] = i[1]
                dic['S-TMSI'] = i[1][-5:]

            elif i[0] == 'ms identity':
                
                if dic['TMSI'] != i[1] and dic['NAS'] == None:
                    dic['NAS-ENC'] = nas_tracking_area_update_complete()
                    dic['UP-COUNT'] += 1 
                    dic['DIR'] = 0
                    nas_encrypted = nas_encrypt(dic)
                    dic['NAS-ENC'] = nas_encrypted 
                    mac_bytes = nas_hash(dic)
                    dic['NAS'] = nas_security_protected_nas_message(2,mac_bytes,bytes([dic['UP-COUNT']%256]),dic['NAS-ENC']) #mudei de 4 para 2
                    dic = eMENU.print_log(dic, "NAS: sending trackingAreaUpdateComplete")
                    
                dic['TMSI'] = i[1]
            elif i[0] == 'location area identification':
                dic['LAI'] = i[1]
                

       

    elif message_type == 75: #tracking area update reject
        dic = eMENU.print_log(dic, "NAS: TrackingAreaUpdateReject received")
        dic['NAS'] = None

    elif message_type == 80: #guti reallocation command
        dic = eMENU.print_log(dic, "NAS: GUTIReallocationCommand received")
        
        for i in nas_list:
            if i[0] == 'guti':   
                dic['GUTI'] = i[1]
                dic['S-TMSI'] = i[1][-5:]     
        dic['NAS-ENC'] = nas_guti_reallocation_complete()
        dic['UP-COUNT'] += 1 
        dic['DIR'] = 0
        nas_encrypted = nas_encrypt(dic)
        dic['NAS-ENC'] = nas_encrypted 
        mac_bytes = nas_hash(dic)
        dic['NAS'] = nas_security_protected_nas_message(2,mac_bytes,bytes([dic['UP-COUNT']%256]),dic['NAS-ENC']) #mudei de 4 para 2
        dic = eMENU.print_log(dic, "NAS: sending GUTIReallocationComplete")
        


    elif message_type == 85: #identity request 
        dic = eMENU.print_log(dic, " NAS: IdentityRequest received")
        for i in nas_list:
            if i[0] == 'identity type':
                if i[1] == 1: # imsi
                    dic['NAS'] = nas_identity_response('9' + dic['IMSI'])
                    dic = eMENU.print_log(dic, "NAS: sending IdentityResponse (IMSI)")
                elif i[1] == 3: # imeisv
                    dic['NAS'] = nas_identity_response('3' + dic['IMEISV'] + 'f')
                    dic = eMENU.print_log(dic, "NAS: sending IdentityResponse (IMEI-SV)")                
                
                if encrypted_flag == True:
                    dic['NAS-ENC'] = dic['NAS'] 
                    dic['UP-COUNT'] += 1 
                    dic['DIR'] = 0
                    nas_encrypted = nas_encrypt(dic)
                    dic['NAS-ENC'] = nas_encrypted 
                    mac_bytes = nas_hash(dic)
                    dic['NAS'] = nas_security_protected_nas_message(2,mac_bytes,bytes([dic['UP-COUNT']%256]),dic['NAS-ENC']) #mudei de 4 para 2



                    
    elif message_type == 96: #emm status    
        dic = eMENU.print_log(dic, "NAS: EMMStatus received")
        dic['NAS'] = None
        
    elif message_type == 97: #emm information    
        dic = eMENU.print_log(dic, "NAS: EMMInformation received")
        dic['NAS'] = None

    elif message_type == 98: #downlink nas transport 
        dic = eMENU.print_log(dic, "NAS: DownlinkNASTransport received")
        dic['NAS'] = None
        
        for i in nas_list:
            if i[0] == "nas message container":
               
                if i[1][1:2] != b'\x04' and i[1][1:2] != b'\x10':
                    if i[1][0] > 128:
                        SMS = bytes([i[1][0]-128]) + b'\x04'
                    else:
                        SMS = bytes([i[1][0]+128]) + b'\x04'

                    dic['NAS-ENC'] = nas_uplink_nas_transport(SMS)
                    dic['UP-COUNT'] += 1 
                    dic['DIR'] = 0
                    nas_encrypted = nas_encrypt(dic)
                    dic['NAS-ENC'] = nas_encrypted 
                    mac_bytes = nas_hash(dic)
                    dic['NAS'] = nas_security_protected_nas_message(2,mac_bytes,bytes([dic['UP-COUNT']%256]),dic['NAS-ENC']) #mudei de 4 para 2
                    dic = eMENU.print_log(dic, "NAS: sending UplinkNASTransport")
                    

                    if i[1][0] < 128:  
                        rp_message_reference = i[1][4:5]
                        SMS = SMS[0:1] + b'\x01\x02\x02'+ rp_message_reference
                        dic['NAS-ENC'] = nas_uplink_nas_transport(SMS)
                        dic['UP-COUNT'] += 1 
                        dic['DIR'] = 0
                        nas_encrypted = nas_encrypt(dic)
                        dic['NAS-ENC'] = nas_encrypted 
                        mac_bytes = nas_hash(dic)
                        dic['NAS-SMS-MT'] = nas_security_protected_nas_message(2,mac_bytes,bytes([dic['UP-COUNT']%256]),dic['NAS-ENC']) #mudei de 4 para 2
                        dic = eMENU.print_log(dic, "NAS: sending UplinkNASTransport")
                    
                    
        
        

    elif message_type == 78: #service reject
        dic = eMENU.print_log(dic, "NAS: ServiceReject received")
        dic['NAS'] = None

    elif message_type == 79: #service accepted
        dic = eMENU.print_log(dic, "NAS: ServiceAccepted received")
        dic['NAS'] = None
        
    elif message_type == 100: #CsServiceNotification received
        dic = eMENU.print_log(dic, "NAS: CsServiceNotification received")
        dic['NAS-ENC'] = nas_extended_service_request(dic['NAS-KEY-SET-IDENTIFIER'], dic['S-TMSI'][1:5])
        dic['UP-COUNT'] += 1 
        dic['DIR'] = 0
    
        mac_bytes = nas_hash(dic)
        dic['NAS'] = nas_security_protected_nas_message(1,mac_bytes,bytes([dic['UP-COUNT']%256]),dic['NAS-ENC']) 
        dic = eMENU.print_log(dic, "NAS: sending ExtendingServiceRequest")
        
        #ativates ue context release after initialsetuprequest by mme
        dic['UECONTEXTRELEASE-CSFB'] = True
        
        
        
        

#### ESM #####

    elif message_type == 193: # activate default eps bearer context request
        dic = eMENU.print_log(dic, "NAS: ActivateDefaultEPSbearerContextRequest received")       
        for i in nas_list:
 
            if i[0] == 'eps bearer identity':
                if i[1] not in dic['EPS-BEARER-IDENTITY']:
                    dic['EPS-BEARER-IDENTITY'].append(i[1])
                    dic['EPS-BEARER-STATE'].append(1)
                    dic['EPS-BEARER-TYPE'].append(0)
                    dic['PDN-ADDRESS'].append('')
                    dic['EPS-BEARER-APN'].append('')
                   
                position = dic['EPS-BEARER-IDENTITY'].index(i[1])
            elif i[0] == 'pdn address':
                dic['PDN-ADDRESS'][position] = i[1]
                pdn_address = eNAS.decode_pdn_address(dic['PDN-ADDRESS'][position])
                
                dic = eMENU.print_log(dic, pdn_address)
                #if dic['PDN-ADDRESS-IPV4'] is not None:
                #    subprocess.call("ip addr del " + dic['PDN-ADDRESS-IPV4'] + "/32 dev tun" + str(dic['IMSI']), shell=True)
                dic['PDN-ADDRESS-IPV4'] = None
                dic['PDN-ADDRESS-IPV6'] = None               
                
                for x in pdn_address:
                    if x[0] == 'ipv4':
                        
                        dic['PDN-ADDRESS-IPV4'] = x[1]
                        #subprocess.call("ip addr add " + x[1] + "/32 dev tun" + str(dic['SESSION-TYPE-TUN']), shell=True)
                    elif x[0] == 'ipv6':
                        # operationg system will process Router Advertisment sent by PGW
                        if dic['PDN-ADDRESS-IPV6'] is not None:
                            subprocess.call("ip -6 addr del " + dic['PDN-ADDRESS-IPV6'] + "/64 dev tun" + str(dic['SESSION-TYPE-TUN']), shell=True)
                        dic['PDN-ADDRESS-IPV6'] = x[1]
                        subprocess.call("ip -6 addr add " + x[1] + "/64 dev tun" + str(dic['SESSION-TYPE-TUN']), shell=True)                            
                

            elif i[0] == 'access point name':
                
                dic['EPS-BEARER-APN'][position] = i[1]
                dic = eMENU.print_log(dic, eNAS.decode_apn(dic['EPS-BEARER-APN'][position]))
                        
        dic['NAS-ENC'] = nas_activate_default_eps_bearer_context_accept(dic['EPS-BEARER-IDENTITY'][position],None)
        dic['UP-COUNT'] += 1 
        dic['DIR'] = 0
        nas_encrypted = nas_encrypt(dic)
        dic['NAS-ENC'] = nas_encrypted 
        mac_bytes = nas_hash(dic)
        dic['NAS'] = nas_security_protected_nas_message(2,mac_bytes,bytes([dic['UP-COUNT']%256]),dic['NAS-ENC']) #mudei de 4 para 2
        dic = eMENU.print_log(dic, "NAS: sending ActivateDefaultEPSbearerContextAccept")


    elif message_type == 197: # 
        dic = eMENU.print_log(dic, "NAS: ActivateDedicatedEPSbearerContextRequest received") 
        for i in nas_list:
 
            if i[0] == 'eps bearer identity':
                if i[1] not in dic['EPS-BEARER-IDENTITY']:
                    dic['EPS-BEARER-IDENTITY'].append(i[1])
                    dic['EPS-BEARER-STATE'].append(1)
                    dic['EPS-BEARER-TYPE'].append(0)
                    dic['PDN-ADDRESS'].append('')
                    dic['EPS-BEARER-APN'].append('')
                   
                position = dic['EPS-BEARER-IDENTITY'].index(i[1])        
        dic['NAS-ENC'] = nas_activate_dedicated_eps_bearer_context_accept(dic['EPS-BEARER-IDENTITY'][position],None)
        dic['UP-COUNT'] += 1 
        dic['DIR'] = 0
        nas_encrypted = nas_encrypt(dic)
        dic['NAS-ENC'] = nas_encrypted 
        mac_bytes = nas_hash(dic)
        dic['NAS'] = nas_security_protected_nas_message(2,mac_bytes,bytes([dic['UP-COUNT']%256]),dic['NAS-ENC']) #mudei de 4 para 2
        dic = eMENU.print_log(dic, "NAS: sending ActivateDedicatedEPSbearerContextAccept")


    elif message_type == 201: #modify eps bearer context request
        dic = eMENU.print_log(dic, "NAS: ModifyEPSBearerContextRequest received")
        for i in nas_list:
            if i[0] == 'eps bearer identity':
                bearer = i[1]
                
        dic['NAS-ENC'] = nas_modify_eps_bearer_context_accept(bearer,None)
        dic['UP-COUNT'] += 1 
        dic['DIR'] = 0
        nas_encrypted = nas_encrypt(dic)
        dic['NAS-ENC'] = nas_encrypted 
        mac_bytes = nas_hash(dic)
        dic['NAS'] = nas_security_protected_nas_message(2,mac_bytes,bytes([dic['UP-COUNT']%256]),dic['NAS-ENC']) #mudei de 4 para 2
        dic = eMENU.print_log(dic, "NAS: sending ModifyEPSBearerContextAccept")        
        
    elif message_type == 205: #deactivate EPS Bearer context request
        dic = eMENU.print_log(dic, "NAS: DeactivateEPSbearerContextRequest received")  
        for i in nas_list:
 
            if i[0] == 'eps bearer identity':
                bearer = i[1]
                if i[1] in dic['EPS-BEARER-IDENTITY']:
                    position = dic['EPS-BEARER-IDENTITY'].index(i[1])
                    
                    dic['EPS-BEARER-IDENTITY'].pop(position)
                    dic['EPS-BEARER-STATE'].pop(position)
                    dic['EPS-BEARER-TYPE'].pop(position)
                    dic['PDN-ADDRESS'].pop(position)
                    dic['EPS-BEARER-APN'].pop(position)
                   

                        
        dic['NAS-ENC'] = nas_deactivate_eps_bearer_context_accept(bearer,0,None)
        dic['UP-COUNT'] += 1 
        dic['DIR'] = 0
        nas_encrypted = nas_encrypt(dic)
        dic['NAS-ENC'] = nas_encrypted 
        mac_bytes = nas_hash(dic)
        dic['NAS'] = nas_security_protected_nas_message(2,mac_bytes,bytes([dic['UP-COUNT']%256]),dic['NAS-ENC']) #mudei de 4 para 2
        dic = eMENU.print_log(dic, "NAS: sending DeactivateEPSbearerContextAccept")       
        
        
    elif message_type == 209: #PDN Connectivity reject
        dic = eMENU.print_log(dic, "NAS: PDNConnectivityReject received")
        dic = eMENU.print_log(dic, [nas_list[-1]])
       
        dic['NAS'] = None
        
        
    elif message_type == 217: #esm information request
        dic = eMENU.print_log(dic, "NAS: ESMInformationRequest received")
        dic['NAS-ENC'] = nas_esm_information_response(0,1,return_apn(dic['APN']),None)
        dic['UP-COUNT'] += 1 
        dic['DIR'] = 0
        nas_encrypted = nas_encrypt(dic)
        dic['NAS-ENC'] = nas_encrypted 
        mac_bytes = nas_hash(dic)
        dic['NAS'] = nas_security_protected_nas_message(2,mac_bytes,bytes([dic['UP-COUNT']%256]),dic['NAS-ENC']) #mudei de 4 para 2
        dic = eMENU.print_log(dic, "NAS: sending ESMInformationResponse")
        
        
    elif message_type == 235:
        dic = eMENU.print_log(dic, "NAS: ESMDataTransport received")    
        for i in nas_list: 
            if i[0] == 'user data container':
                #os.write(dic['NBIOT-TUN'],i[1])
                pass
        dic['NAS'] = None
        
            
    else:   # generic rule to not send NAS if messasge type not known, or handle yet by the function
        dic = eMENU.print_log(dic, "NAS: MessageType =" + str(message_type) + " received")
        dic['NAS'] = None

    
    return dic 




###############
#  S1AP Msg   #
###############
def InitialUEMessage(dic):
    IEs = []
    IEs.append({'id': 8, 'value': ('ENB-UE-S1AP-ID', dic['ENB-UE-S1AP-ID']), 'criticality': 'reject'})
    IEs.append({'id': 26, 'value': ('NAS-PDU', dic['NAS']), 'criticality': 'reject'})
    if dic['SESSION-TYPE'] == "4G" or dic['SESSION-TYPE'] == "5G":
        IEs.append({'id': 67, 'value': ('TAI', {'pLMNidentity': dic['ENB-PLMN'], 'tAC': dic['ENB-TAC']}), 'criticality': 'reject'})
    elif dic['SESSION-TYPE'] == "NBIOT":
        IEs.append({'id': 67, 'value': ('TAI', {'pLMNidentity': dic['ENB-PLMN'], 'tAC': dic['ENB-TAC-NBIOT']}), 'criticality': 'reject'})        
        
    IEs.append({'id': 100, 'value': ('EUTRAN-CGI', {'cell-ID': (dic['ENB-CELLID'], 28), 'pLMNidentity': dic['ENB-PLMN']}), 'criticality': 'ignore'})
    if dic['ATTACH-TYPE'] == 6: #emergency
        IEs.append({'id': 134, 'value': ('RRC-Establishment-Cause', 'emergency'), 'criticality': 'ignore'})
    else:    
        IEs.append({'id': 134, 'value': ('RRC-Establishment-Cause', 'mo-Signalling'), 'criticality': 'ignore'})
    
    if dic['S-TMSI'] != None:
        IEs.append({'id': 96, 'value': ('S-TMSI', {'mMEC': dic['S-TMSI'][0:1], 'm-TMSI': dic['S-TMSI'][1:5]}), 'criticality': 'reject'})
#    IEs.append({'id': 75, 'value': ('GUMMEI', {'pLMN-Identity': dic['ENB-PLMN'], 'mME-Group-ID': dic['MME-GROUP-ID'], 'mME-Code': dic['MME-CODE']}), 'criticality': 'reject'})
   
    val = ('initiatingMessage', {'procedureCode': 12, 'value': ('InitialUEMessage', {'protocolIEs': IEs}), 'criticality': 'ignore'})
    dic = eMENU.print_log(dic, "S1AP: sending InitialUEMessage")
    return val


def UplinkNASTransport(dic):

    IEs = []
    IEs.append({'id': 0, 'value': ('MME-UE-S1AP-ID', dic['MME-UE-S1AP-ID']), 'criticality': 'reject'})
    IEs.append({'id': 8, 'value': ('ENB-UE-S1AP-ID', dic['ENB-UE-S1AP-ID']), 'criticality': 'reject'})
    IEs.append({'id': 26, 'value': ('NAS-PDU', dic['NAS']), 'criticality': 'reject'})
    IEs.append({'id': 100, 'value': ('EUTRAN-CGI', {'cell-ID': (dic['ENB-CELLID'], 28), 'pLMNidentity': dic['ENB-PLMN']}), 'criticality': 'ignore'})   
    if dic['SESSION-TYPE'] == "4G" or dic['SESSION-TYPE'] == "5G":
        IEs.append({'id': 67, 'value': ('TAI', {'pLMNidentity': dic['ENB-PLMN'], 'tAC': dic['ENB-TAC']}), 'criticality': 'ignore'})
    elif dic['SESSION-TYPE'] == "NBIOT":        
        IEs.append({'id': 67, 'value': ('TAI', {'pLMNidentity': dic['ENB-PLMN'], 'tAC': dic['ENB-TAC-NBIOT']}), 'criticality': 'ignore'})

    val = ('initiatingMessage', {'procedureCode': 13, 'value': ('UplinkNASTransport', {'protocolIEs': IEs}), 'criticality': 'ignore'})
        
    dic = eMENU.print_log(dic, "S1AP: sending UplinkNASTransport")
    return val     

def ProcessLocationReportingControl(IEs, dic):

    for i in IEs:
        if i['id'] == 98:
            request_type = i['value']


    IEs = []
    IEs.append({'id': 0, 'value': ('MME-UE-S1AP-ID', dic['MME-UE-S1AP-ID']), 'criticality': 'reject'})
    IEs.append({'id': 8, 'value': ('ENB-UE-S1AP-ID', dic['ENB-UE-S1AP-ID']), 'criticality': 'reject'})
    IEs.append({'id': 100, 'value': ('EUTRAN-CGI', {'cell-ID': (dic['ENB-CELLID'], 28), 'pLMNidentity': dic['ENB-PLMN']}), 'criticality': 'ignore'})   
    if dic['SESSION-TYPE'] == "4G" or dic['SESSION-TYPE'] == "5G":
        IEs.append({'id': 67, 'value': ('TAI', {'pLMNidentity': dic['ENB-PLMN'], 'tAC': dic['ENB-TAC']}), 'criticality': 'ignore'})
    elif dic['SESSION-TYPE'] == "NBIOT":        
        IEs.append({'id': 67, 'value': ('TAI', {'pLMNidentity': dic['ENB-PLMN'], 'tAC': dic['ENB-TAC-NBIOT']}), 'criticality': 'ignore'})
        
    IEs.append({'id': 98, 'value': request_type, 'criticality': 'ignore'})        
    

    val = ('initiatingMessage', {'procedureCode': 33, 'value': ('LocationReport', {'protocolIEs': IEs}), 'criticality': 'ignore'})     
    dic = eMENU.print_log(dic, "S1AP: sending LocationReport")
    return val, dic


def ProcessDownlinkNASTransport(IEs, dic):
    for i in IEs:
        if i['id'] == 0:
            mme_ue_s1ap_id = i['value'][1]
            dic['MME-UE-S1AP-ID'] = mme_ue_s1ap_id
        elif i['id'] == 26:
            nas_pdu = i['value'][1]
            dic['NAS'] = nas_pdu
            
    dic = ProcessDownlinkNAS(dic)
    
    val = []
    
    if dic['NAS'] != None or dic['NAS-SMS-MT'] != None:
        if dic['NAS'] != None:
            IEs = []
            if dic['AUTH-ERROR']:
                IEs.append({'id': 0, 'value': ('MME-UE-S1AP-ID', dic['MME-UE-S1AP-ID']), 'criticality': 'reject'})
                IEs.append({'id': 8, 'value': ('ENB-UE-S1AP-ID', dic['ENB-UE-S1AP-ID']), 'criticality': 'reject'})
                IEs.append({'id': 2, 'value': ('Cause', ('radioNetwork', 'radio-connection-with-ue-lost')), 'criticality': 'ignore'})
                IEs.append({'id': 26, 'value': ('NAS-PDU',dic['NAS']), 'criticality': 'reject'})
                val.append(('initiatingMessage', {'procedureCode': 16, 'value': ('NASNonDeliveryIndication', {'protocolIEs': IEs}), 'criticality': 'ignore'}))
            else:   
                IEs.append({'id': 0, 'value': ('MME-UE-S1AP-ID', dic['MME-UE-S1AP-ID']), 'criticality': 'reject'})
                IEs.append({'id': 8, 'value': ('ENB-UE-S1AP-ID', dic['ENB-UE-S1AP-ID']), 'criticality': 'reject'})
                IEs.append({'id': 26, 'value': ('NAS-PDU', dic['NAS']), 'criticality': 'reject'})
                IEs.append({'id': 100, 'value': ('EUTRAN-CGI', {'cell-ID': (dic['ENB-CELLID'], 28), 'pLMNidentity': dic['ENB-PLMN']}), 'criticality': 'ignore'})   
                if dic['SESSION-TYPE'] == "4G" or dic['SESSION-TYPE'] == "5G":
                    IEs.append({'id': 67, 'value': ('TAI', {'pLMNidentity': dic['ENB-PLMN'], 'tAC': dic['ENB-TAC']}), 'criticality': 'ignore'})
                elif dic['SESSION-TYPE'] == "NBIOT":            
                    IEs.append({'id': 67, 'value': ('TAI', {'pLMNidentity': dic['ENB-PLMN'], 'tAC': dic['ENB-TAC-NBIOT']}), 'criticality': 'ignore'})
                val.append(('initiatingMessage', {'procedureCode': 13, 'value': ('UplinkNASTransport', {'protocolIEs': IEs}), 'criticality': 'ignore'}))
            dic = eMENU.print_log(dic, "S1AP: sending UplinkNASTransport")
        if dic['NAS-SMS-MT'] != None:
            IEs = []
            IEs.append({'id': 0, 'value': ('MME-UE-S1AP-ID', dic['MME-UE-S1AP-ID']), 'criticality': 'reject'})
            IEs.append({'id': 8, 'value': ('ENB-UE-S1AP-ID', dic['ENB-UE-S1AP-ID']), 'criticality': 'reject'})
            IEs.append({'id': 26, 'value': ('NAS-PDU', dic['NAS-SMS-MT']), 'criticality': 'reject'})
            IEs.append({'id': 100, 'value': ('EUTRAN-CGI', {'cell-ID': (dic['ENB-CELLID'], 28), 'pLMNidentity': dic['ENB-PLMN']}), 'criticality': 'ignore'})   
            if dic['SESSION-TYPE'] == "4G" or dic['SESSION-TYPE'] == "5G":
                IEs.append({'id': 67, 'value': ('TAI', {'pLMNidentity': dic['ENB-PLMN'], 'tAC': dic['ENB-TAC']}), 'criticality': 'ignore'})
            elif dic['SESSION-TYPE'] == "NBIOT":            
                IEs.append({'id': 67, 'value': ('TAI', {'pLMNidentity': dic['ENB-PLMN'], 'tAC': dic['ENB-TAC-NBIOT']}), 'criticality': 'ignore'})
            val.append(('initiatingMessage', {'procedureCode': 13, 'value': ('UplinkNASTransport', {'protocolIEs': IEs}), 'criticality': 'ignore'}))
            dic = eMENU.print_log(dic, "S1AP: sending UplinkNASTransport")        
            
            dic['NAS-SMS-MT'] = None
        return val, dic
    else:
        return [None], dic


         
def ProcessInitialContextSetupRequest(IEs, dic):
    for i in IEs:
        if i['id'] == 0:
            mme_ue_s1ap_id = i['value'][1]
            dic['MME-UE-S1AP-ID'] = mme_ue_s1ap_id
        elif i['id'] == 24:
            eRAB_list = i['value'][1]
            
            Num_eRAB = len(eRAB_list)
            
            nas = []
            
            for m in range(Num_eRAB):
            
                first_eRAB = eRAB_list[m]['value'][1]
                e_RAB_id = first_eRAB['e-RAB-ID']
                
                if e_RAB_id not in dic['RAB-ID']:
                    dic['RAB-ID'].append(e_RAB_id)
                    dic['SGW-GTP-ADDRESS'].append(None)
                    dic['SGW-TEID'].append(None)
                    
                position = dic['RAB-ID'].index(e_RAB_id)                
                dic['SGW-GTP-ADDRESS'][position] = (first_eRAB['transportLayerAddress'][0]).to_bytes(4, byteorder='big')
                dic['SGW-TEID'][position] = first_eRAB['gTP-TEID']
                if 'nAS-PDU' in first_eRAB:
                    nas.append(first_eRAB['nAS-PDU'])
              
                else:
                    
                    nas.append(None)

            #uses the last pdn as the gtp-u
            if len(dic['SGW-GTP-ADDRESS']) > 0:
                #os.write(dic['PIPE-OUT-GTPU-ENCAPSULATE'],dic['GTP-U'] + dic['SGW-GTP-ADDRESS'][-1] + dic['SGW-TEID'][-1])
                #os.write(dic['PIPE-OUT-GTPU-DECAPSULATE'],dic['GTP-U'] + dic['SGW-GTP-ADDRESS'][-1] + b'\x00\x00\x00' + bytes([dic['RAB-ID'][-1]])) 
                global gtp_dict 
                gtp_dict[dic['GTP-KEY']] =((dic['SGW-TEID'])[-1],(dic['SGW-GTP-ADDRESS'])[-1])      
                

        
    val = []
    
    IEs = []
    IEs.append({'id': 0, 'value': ('MME-UE-S1AP-ID', dic['MME-UE-S1AP-ID']), 'criticality': 'ignore'})
    IEs.append({'id': 8, 'value': ('ENB-UE-S1AP-ID', dic['ENB-UE-S1AP-ID']), 'criticality': 'ignore'})
    IEs_RABs_List = []
    for m in range(Num_eRAB):
        e_RAB_id = eRAB_list[m]['value'][1]['e-RAB-ID']
        IEs_RAB = {'id': 50, 'value': ('E-RABSetupItemCtxtSURes', {'e-RAB-ID': e_RAB_id, 'transportLayerAddress': (dic['ENB-GTP-ADDRESS-INT'], 32), 'gTP-TEID': (struct.pack('>I', upteid_get()))[1:] + bytes([e_RAB_id]) }), 'criticality': 'ignore'}
        IEs_RABs_List.append(IEs_RAB)
        
    IEs.append({'id': 51, 'value': ('E-RABSetupListCtxtSURes', IEs_RABs_List), 'criticality': 'ignore'})   
    val.append(('successfulOutcome', {'procedureCode': 9, 'value': ('InitialContextSetupResponse', {'protocolIEs': IEs}), 'criticality': 'ignore'}))
    dic = eMENU.print_log(dic, "S1AP: sending InitialContextSetupResponse")
 
    nas_processed = []
    
    for nas_msg in nas:
        if nas_msg is not None:
            dic['NAS'] = nas_msg
            dic = ProcessDownlinkNAS(dic)
            if dic['NAS'] != None:
                nas_processed.append(dic['NAS'])            
            else:
                nas_processed.append(None)

    for nas_msg in nas_processed:
        if nas_msg != None:
            IEs = []
            IEs.append({'id': 0, 'value': ('MME-UE-S1AP-ID', dic['MME-UE-S1AP-ID']), 'criticality': 'reject'})
            IEs.append({'id': 8, 'value': ('ENB-UE-S1AP-ID', dic['ENB-UE-S1AP-ID']), 'criticality': 'reject'})
            IEs.append({'id': 26, 'value': ('NAS-PDU', nas_msg), 'criticality': 'reject'})
            IEs.append({'id': 100, 'value': ('EUTRAN-CGI', {'cell-ID': (dic['ENB-CELLID'], 28), 'pLMNidentity': dic['ENB-PLMN']}), 'criticality': 'ignore'})   
            if dic['SESSION-TYPE'] == "4G" or dic['SESSION-TYPE'] == "5G":        
                IEs.append({'id': 67, 'value': ('TAI', {'pLMNidentity': dic['ENB-PLMN'], 'tAC': dic['ENB-TAC']}), 'criticality': 'ignore'})
            elif dic['SESSION-TYPE'] == "NBIOT":            
                IEs.append({'id': 67, 'value': ('TAI', {'pLMNidentity': dic['ENB-PLMN'], 'tAC': dic['ENB-TAC-NBIOT']}), 'criticality': 'ignore'})
            val.append(('initiatingMessage', {'procedureCode': 13, 'value': ('UplinkNASTransport', {'protocolIEs': IEs}), 'criticality': 'ignore'}))
      
            dic = eMENU.print_log(dic, "S1AP: sending UplinkNASTransport")
            
            
    if dic['UECONTEXTRELEASE-CSFB'] == True:            
        val.append(UEContextReleaseRequest(dic))
        
    return val, dic


def ProcessERABSetupRequest(IEs, dic):
    for i in IEs:
        if i['id'] == 0:
            mme_ue_s1ap_id = i['value'][1]
            dic['MME-UE-S1AP-ID'] = mme_ue_s1ap_id
        elif i['id'] == 16:
            eRAB_list = i['value'][1]
            
            Num_eRAB = len(eRAB_list)
            
            nas = []
            
            for m in range(Num_eRAB):
            
                first_eRAB = eRAB_list[m]['value'][1]
                e_RAB_id = first_eRAB['e-RAB-ID']
                
                if e_RAB_id not in dic['RAB-ID']:
                    dic['RAB-ID'].append(e_RAB_id)
                    dic['SGW-GTP-ADDRESS'].append(None)
                    dic['SGW-TEID'].append(None)
     
                position = dic['RAB-ID'].index(e_RAB_id)
                                        
                dic['SGW-GTP-ADDRESS'][position] = (first_eRAB['transportLayerAddress'][0]).to_bytes(4, byteorder='big')
                dic['SGW-TEID'][position] = first_eRAB['gTP-TEID']
                if 'nAS-PDU' in first_eRAB:
                    nas.append(first_eRAB['nAS-PDU'])
                    #dic['NAS'] = first_eRAB['nAS-PDU']
                else:
                    nas.append(None)
                    #dic['NAS'] = None
            
            if len(dic['SGW-GTP-ADDRESS']) > 0:
                #os.write(dic['PIPE-OUT-GTPU-ENCAPSULATE'],dic['GTP-U'] + dic['SGW-GTP-ADDRESS'][-1] + dic['SGW-TEID'][-1])
                #os.write(dic['PIPE-OUT-GTPU-DECAPSULATE'],dic['GTP-U'] + dic['SGW-GTP-ADDRESS'][-1] + b'\x00\x00\x00' + bytes([dic['RAB-ID'][-1]]))  
                pass          
                
    val = []
    
    IEs = []
    IEs.append({'id': 0, 'value': ('MME-UE-S1AP-ID', dic['MME-UE-S1AP-ID']), 'criticality': 'ignore'})
    IEs.append({'id': 8, 'value': ('ENB-UE-S1AP-ID', dic['ENB-UE-S1AP-ID']), 'criticality': 'ignore'})
    IEs_RABs_List = []
    for m in range(Num_eRAB):
        e_RAB_id = eRAB_list[m]['value'][1]['e-RAB-ID']
        IEs_RAB = {'id': 39, 'value': ('E-RABSetupItemBearerSURes', {'e-RAB-ID': e_RAB_id, 'transportLayerAddress': (dic['ENB-GTP-ADDRESS-INT'], 32), 'gTP-TEID': b'\x00\x00\x00' + bytes([e_RAB_id]) }), 'criticality': 'ignore'}
        IEs_RABs_List.append(IEs_RAB)
        
    IEs.append({'id': 28, 'value': ('E-RABSetupListBearerSURes', IEs_RABs_List), 'criticality': 'ignore'})   
    val.append(('successfulOutcome', {'procedureCode': 5, 'value': ('E-RABSetupResponse', {'protocolIEs': IEs}), 'criticality': 'ignore'}))
    dic = eMENU.print_log(dic, "S1AP: sending ERABSetupResponse")

    #dic = ProcessDownlinkNAS(dic)
    
    nas_processed = []
    
    for nas_msg in nas:
        if nas_msg is not None:
            dic['NAS'] = nas_msg
            dic = ProcessDownlinkNAS(dic)
            if dic['NAS'] != None:
                nas_processed.append(dic['NAS'])            
            else:
                nas_processed.append(None)
    

    for nas_msg in nas_processed:
        if nas_msg != None:
            IEs = []
            IEs.append({'id': 0, 'value': ('MME-UE-S1AP-ID', dic['MME-UE-S1AP-ID']), 'criticality': 'reject'})
            IEs.append({'id': 8, 'value': ('ENB-UE-S1AP-ID', dic['ENB-UE-S1AP-ID']), 'criticality': 'reject'})
            IEs.append({'id': 26, 'value': ('NAS-PDU', nas_msg), 'criticality': 'reject'})
            IEs.append({'id': 100, 'value': ('EUTRAN-CGI', {'cell-ID': (dic['ENB-CELLID'], 28), 'pLMNidentity': dic['ENB-PLMN']}), 'criticality': 'ignore'})  
            if dic['SESSION-TYPE'] == "4G" or dic['SESSION-TYPE'] == "5G":          
                IEs.append({'id': 67, 'value': ('TAI', {'pLMNidentity': dic['ENB-PLMN'], 'tAC': dic['ENB-TAC']}), 'criticality': 'ignore'})
            elif dic['SESSION-TYPE'] == "NBIOT":              
                IEs.append({'id': 67, 'value': ('TAI', {'pLMNidentity': dic['ENB-PLMN'], 'tAC': dic['ENB-TAC-NBIOT']}), 'criticality': 'ignore'})
            val.append(('initiatingMessage', {'procedureCode': 13, 'value': ('UplinkNASTransport', {'protocolIEs': IEs}), 'criticality': 'ignore'}))    
      
            dic = eMENU.print_log(dic, "S1AP: sending UplinkNASTransport")
       
        
    return val, dic



def ProcessERABReleaseCommand(IEs, dic):
    for i in IEs:
        if i['id'] == 33:
            eRAB_list = i['value'][1]
            
            Num_eRAB = len(eRAB_list)
            
            for m in range(Num_eRAB):
            
                first_eRAB = eRAB_list[m]['value'][1]
                e_RAB_id = first_eRAB['e-RAB-ID']
                
                if e_RAB_id in dic['RAB-ID']:
                    position = dic['EPS-BEARER-IDENTITY'].index(e_RAB_id)
                    dic['RAB-ID'].pop(position)
                    dic['SGW-GTP-ADDRESS'].pop(position)
                    dic['SGW-TEID'].pop(position)
            
            if len(dic['SGW-GTP-ADDRESS']) > 0:
                #os.write(dic['PIPE-OUT-GTPU-ENCAPSULATE'],dic['GTP-U'] + dic['SGW-GTP-ADDRESS'][-1] + dic['SGW-TEID'][-1])
                #os.write(dic['PIPE-OUT-GTPU-DECAPSULATE'],dic['GTP-U'] + dic['SGW-GTP-ADDRESS'][-1] + b'\x00\x00\x00' + bytes([dic['RAB-ID'][-1]]))
                pass
     
        elif i['id'] == 26: #nas        
            nas_pdu = i['value'][1]
            dic['NAS'] = nas_pdu
            
    dic = ProcessDownlinkNAS(dic)                    

    IEs = []
    IEs.append({'id': 0, 'value': ('MME-UE-S1AP-ID', dic['MME-UE-S1AP-ID']), 'criticality': 'ignore'})
    IEs.append({'id': 8, 'value': ('ENB-UE-S1AP-ID', dic['ENB-UE-S1AP-ID']), 'criticality': 'ignore'})
    IEs_RABs_List = []
    for m in range(Num_eRAB):
        e_RAB_id = eRAB_list[m]['value'][1]['e-RAB-ID']
        IEs_RAB = {'id': 15, 'value': ('E-RABReleaseItemBearerRelComp', {'e-RAB-ID': e_RAB_id}), 'criticality': 'ignore'}
        IEs_RABs_List.append(IEs_RAB)
        
    IEs.append({'id': 69, 'value': ('E-RABReleaseListBearerRelComp', IEs_RABs_List), 'criticality': 'ignore'})   
    val = ('successfulOutcome', {'procedureCode': 7, 'value': ('E-RABReleaseResponse', {'protocolIEs': IEs}), 'criticality': 'ignore'})
    dic = eMENU.print_log(dic, "S1AP: sending ERABSetupResponse")
    
    val2 = None
    if dic['NAS'] != None:
        IEs = []
        IEs.append({'id': 0, 'value': ('MME-UE-S1AP-ID', dic['MME-UE-S1AP-ID']), 'criticality': 'reject'})
        IEs.append({'id': 8, 'value': ('ENB-UE-S1AP-ID', dic['ENB-UE-S1AP-ID']), 'criticality': 'reject'})
        IEs.append({'id': 26, 'value': ('NAS-PDU', dic['NAS']), 'criticality': 'reject'})
        IEs.append({'id': 100, 'value': ('EUTRAN-CGI', {'cell-ID': (dic['ENB-CELLID'], 28), 'pLMNidentity': dic['ENB-PLMN']}), 'criticality': 'ignore'})   
        if dic['SESSION-TYPE'] == "4G" or dic['SESSION-TYPE'] == "5G": 
            IEs.append({'id': 67, 'value': ('TAI', {'pLMNidentity': dic['ENB-PLMN'], 'tAC': dic['ENB-TAC']}), 'criticality': 'ignore'})
        elif dic['SESSION-TYPE'] == "NBIOT":     
            IEs.append({'id': 67, 'value': ('TAI', {'pLMNidentity': dic['ENB-PLMN'], 'tAC': dic['ENB-TAC-NBIOT']}), 'criticality': 'ignore'})
        val2 = ('initiatingMessage', {'procedureCode': 13, 'value': ('UplinkNASTransport', {'protocolIEs': IEs}), 'criticality': 'ignore'})    
      
        dic = eMENU.print_log(dic, "S1AP: sending UplinkNASTransport")
    return [val, val2] , dic





def ProcessUEContextReleaseCommand(rec_dic,IEs, dic):
    #assumes only one session so no need to check MME-UE-S1AP-ID and ENB-UE-S1AP-ID
    IEs = []
    #if dic['MME-UE-S1AP-ID-OLD'] == None:
    #    IEs.append({'id': 0, 'value': ('MME-UE-S1AP-ID', dic['MME-UE-S1AP-ID']), 'criticality': 'ignore'})
    #    IEs.append({'id': 8, 'value': ('ENB-UE-S1AP-ID', dic['ENB-UE-S1AP-ID']), 'criticality': 'ignore'})
    #else:
    #    IEs.append({'id': 0, 'value': ('MME-UE-S1AP-ID', dic['MME-UE-S1AP-ID-OLD']), 'criticality': 'ignore'})
    #    IEs.append({'id': 8, 'value': ('ENB-UE-S1AP-ID', dic['ENB-UE-S1AP-ID-OLD']), 'criticality': 'ignore'})   
    for key,value in rec_dic.items():
        if isinstance(value,tuple):
            for dic_check in value:
                if isinstance(dic_check,dict):
                    for id_pair in dic_check['protocolIEs']:
                        if id_pair['id'] == 99:
                            for recv_id in id_pair['value']:
                                if isinstance(recv_id,tuple):
                                    if isinstance(recv_id[1],dict):
                                        IEs.append({'id': 0, 'value': ('MME-UE-S1AP-ID', recv_id[1]['mME-UE-S1AP-ID']), 'criticality': 'ignore'})
                                        IEs.append({'id': 8, 'value': ('ENB-UE-S1AP-ID', recv_id[1]['eNB-UE-S1AP-ID']), 'criticality': 'ignore'})   

    val = ('successfulOutcome', {'procedureCode': 23, 'value': ('UEContextReleaseComplete', {'protocolIEs': IEs}), 'criticality': 'ignore'})
    dic = eMENU.print_log(dic, "S1AP: sending UEContextReleaseComplete")
    
    # context release set s1ap-id to 0: means disable
    dic['MME-UE-S1AP-ID'] = 0
    
    if dic['GTP-U'] != b'\x02' and len(dic['SGW-GTP-ADDRESS']) > 0:
       #disable but do not change variable value (i.e. to activate in case service request is initiated)
        #os.write(dic['PIPE-OUT-GTPU-ENCAPSULATE'],b'\x02' + dic['SGW-GTP-ADDRESS'][-1] + dic['SGW-TEID'][-1])
       # os.write(dic['PIPE-OUT-GTPU-DECAPSULATE'],b'\x02' + dic['SGW-GTP-ADDRESS'][-1] + b'\x00\x00\x00' + bytes([dic['RAB-ID'][-1]]))
       pass
    dic = eMENU.print_log(dic, "GTP-U: Deactivation due to ContextRelease")
    
    #if uecontext release was triggered by csfb
    if dic['UECONTEXTRELEASE-CSFB'] == True:
        dic['UECONTEXTRELEASE-CSFB'] = False
        
    return val, dic



def ProcessUEContextModificationRequest(IEs, dic):
    
        
    val = []
    
    IEs = []
    IEs.append({'id': 0, 'value': ('MME-UE-S1AP-ID', dic['MME-UE-S1AP-ID']), 'criticality': 'ignore'})
    IEs.append({'id': 8, 'value': ('ENB-UE-S1AP-ID', dic['ENB-UE-S1AP-ID']), 'criticality': 'ignore'})

    val.append(('successfulOutcome', {'procedureCode': 21, 'value': ('UEContextModificationResponse', {'protocolIEs': IEs}), 'criticality': 'ignore'}))
    dic = eMENU.print_log(dic, "S1AP: sending UEContextModificationResponse")
             
           
    if dic['UECONTEXTRELEASE-CSFB'] == True:            
        val.append(UEContextReleaseRequest(dic))
        
    return val, dic



def ProcessPaging(IEs, dic):
    
    val = None
    SEND_NAS = False
    for i in IEs:
        if i['id'] == 43:
            if i['value'][1][0] == 's-TMSI':
                MME_CODE = i['value'][1][1]['mMEC']
                M_TMSI = i['value'][1][1]['m-TMSI']
                if dic['S-TMSI'] == MME_CODE + M_TMSI:  # envia service request
                    SEND_NAS = True
                             
            else:
                dic['NAS'] = None

        elif i['id'] == 109: #CNDomain
            
            if i['value'][1] == 'ps' and SEND_NAS == True:
                if dic['SESSION-TYPE'] == "4G" or dic['SESSION-TYPE'] == "5G":
                    dic = ProcessUplinkNAS('service request', dic)
                elif dic['SESSION-TYPE'] == "NBIOT":
                    dic['CPSR-TYPE'] = 1
                    dic = ProcessUplinkNAS('control plane service request', dic)            
                
            
            elif i['value'][1] == 'cs' and SEND_NAS == True:
                dic = ProcessUplinkNAS('extended service request', dic) 
            
            
            
    if dic['NAS'] != None:
        val = InitialUEMessage(dic)

    return val, dic


def UEContextReleaseRequest(dic):

    #assumes only one session so no need to check MME-UE-S1AP-ID and ENB-UE-S1AP-ID
    IEs = []
    IEs.append({'id': 0, 'value': ('MME-UE-S1AP-ID', dic['MME-UE-S1AP-ID']), 'criticality': 'ignore'})
    IEs.append({'id': 8, 'value': ('ENB-UE-S1AP-ID', dic['ENB-UE-S1AP-ID']), 'criticality': 'ignore'})
    if dic['UECONTEXTRELEASE-CSFB'] == False:
        IEs.append({'id': 2, 'value': ('Cause', ('radioNetwork', 'user-inactivity')), 'criticality': 'ignore'})
    else:
        IEs.append({'id': 2, 'value': ('Cause', ('radioNetwork', 'cs-fallback-triggered')), 'criticality': 'ignore'})
        
  
    val = ('initiatingMessage', {'procedureCode': 18, 'value': ('UEContextReleaseRequest', {'protocolIEs': IEs}), 'criticality': 'ignore'})
    dic = eMENU.print_log(dic, "S1AP: sending UEContextReleaseRequest")
    
    if dic['GTP-U'] != b'\x02' and len(dic['SGW-GTP-ADDRESS']) > 0:
        
        #os.write(dic['PIPE-OUT-GTPU-ENCAPSULATE'],b'\x02' + dic['SGW-GTP-ADDRESS'][-1] + dic['SGW-TEID'][-1])
        #os.write(dic['PIPE-OUT-GTPU-DECAPSULATE'],b'\x02' + dic['SGW-GTP-ADDRESS'][-1] + b'\x00\x00\x00' + bytes([dic['RAB-ID'][-1]]))
        pass
    dic = eMENU.print_log(dic, "GTP-U: Deactivation due to ContextRelease")
        
    return val


def ERABModificationIndication(dic):
    #assumes only one session so no need to check MME-UE-S1AP-ID and ENB-UE-S1AP-ID
    IEs = []
    IEs.append({'id': 0, 'value': ('MME-UE-S1AP-ID', dic['MME-UE-S1AP-ID']), 'criticality': 'ignore'})
    IEs.append({'id': 8, 'value': ('ENB-UE-S1AP-ID', dic['ENB-UE-S1AP-ID']), 'criticality': 'ignore'})
    
    RABList = []
    
    for i in range(len(dic['RAB-ID'])):
        RABList.append({'id': 200, 'value': ('E-RABToBeModifiedItemBearerModInd', {'e-RAB-ID': dic['RAB-ID'][i], 'transportLayerAddress': (dic['ENB-GTP-ADDRESS-INT'], 32), 'dL-GTP-TEID': b'\x00\x00\x00' + bytes([dic['RAB-ID'][i]]) }), 'criticality': 'ignore'})
    IEs.append({'id': 199, 'value': ('E-RABToBeModifiedListBearerModInd', RABList), 'criticality': 'reject'})


    curTime = int(time.time()) + 2208988800 #1900 instead of 1970
    oldcurTime = curTime - 10
    
    startTimestamp = struct.pack("!I", oldcurTime)
    endTimestamp = struct.pack("!I",curTime)
    

    b = {'id': 267, 'value': ('E-RABUsageReportItem', {'startTimestamp': startTimestamp, 'endTimestamp': endTimestamp, 'usageCountUL': 12345678, 'usageCountDL': 9876543}), 'criticality': 'ignore'}

    SecondaryRATDataList = []
    for i in range(len(dic['RAB-ID'])):
        SecondaryRATDataList.append({'id': 265, 'value': ('SecondaryRATDataUsageReportItem', {'e-RAB-ID': dic['RAB-ID'][i], 'secondaryRATType': 'nR', 'e-RABUsageReportList': [b] }), 'criticality': 'ignore'})

    IEs.append({'id': 264, 'value': ('SecondaryRATDataUsageReportList', SecondaryRATDataList), 'criticality': 'ignore'})

    dic = eMENU.print_log(dic, "S1AP: sending E-RABModificationIndication")
    val = ('initiatingMessage', {'procedureCode': 50, 'value': ('E-RABModificationIndication', {'protocolIEs': IEs}), 'criticality': 'reject'})

    return val


def SecondaryRATDataUsageReport(dic):
    #assumes only one session so no need to check MME-UE-S1AP-ID and ENB-UE-S1AP-ID
    IEs = []
    IEs.append({'id': 0, 'value': ('MME-UE-S1AP-ID', dic['MME-UE-S1AP-ID']), 'criticality': 'ignore'})
    IEs.append({'id': 8, 'value': ('ENB-UE-S1AP-ID', dic['ENB-UE-S1AP-ID']), 'criticality': 'ignore'})
    

    curTime = int(time.time()) + 2208988800 #1900 instead of 1970
    oldcurTime = curTime - 10
    
    startTimestamp = struct.pack("!I", oldcurTime)
    endTimestamp = struct.pack("!I",curTime)
    

    b = {'id': 267, 'value': ('E-RABUsageReportItem', {'startTimestamp': startTimestamp, 'endTimestamp': endTimestamp, 'usageCountUL': 12345678, 'usageCountDL': 9876543}), 'criticality': 'ignore'}

    SecondaryRATDataList = []
    for i in range(len(dic['RAB-ID'])):
        SecondaryRATDataList.append({'id': 265, 'value': ('SecondaryRATDataUsageReportItem', {'e-RAB-ID': dic['RAB-ID'][i], 'secondaryRATType': 'nR', 'e-RABUsageReportList': [b] }), 'criticality': 'ignore'})

    IEs.append({'id': 264, 'value': ('SecondaryRATDataUsageReportList', SecondaryRATDataList), 'criticality': 'ignore'})

    dic = eMENU.print_log(dic, "S1AP: sending SecondaryRATDataUsageReport")
    val = ('initiatingMessage', {'procedureCode': 62, 'value': ('SecondaryRATDataUsageReport', {'protocolIEs': IEs}), 'criticality': 'reject'})

    return val

def send_gtpu(session_d):
    try:
        hex_str= bytes.fromhex('30ff0064') + session_d['SGW-TEID'][0] + bytes.fromhex('4500006493d9000040015652') + session_d['PDN-ADDRESS'][0][1:] + bytes.fromhex('0808080808006ace039600015635c5637dfc0b0008090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4041424344454647')
        gtp=hex_str
        pkt = IP(src="192.168.197.180",dst="192.168.197.201")/UDP(sport=2152,dport=2152)/Raw(gtp)
        for i in range(10):
            send(pkt,iface="ens32",verbose=0)
    except:
        pass
def ProcessS1AP(type,pdu_dict, client, session_dict):
    
    if type == 'initiatingMessage':
        procedure, protocolIEs_list = pdu_dict['value'][0], pdu_dict['value'][1]['protocolIEs']
        
        #Non UE Related:
        if procedure == 'MMEConfigurationUpdate':
            session_dict = eMENU.print_log(session_dict, "S1AP: MMEConfigurationUpdate received")
            answer, session_dict = MMEConfigurationUpdateAcknowledge(protocolIEs_list, session_dict)
            PDU.set_val(answer)
            message = PDU.to_aper()
            client = set_stream(client, 0)
            bytes_sent = client.send(message)
            client = set_stream(client, 1)
        
        #UE Related:
        elif procedure == 'DownlinkNASTransport':
            session_dict = eMENU.print_log(session_dict, "S1AP: DownlinkNASTransport received")
            answer_list, session_dict = ProcessDownlinkNASTransport(protocolIEs_list, session_dict)
            for answer in answer_list:
                if answer != None:
                    PDU.set_val(answer)
                    message = PDU.to_aper()               
                    bytes_sent = client.send(message)
        
        elif procedure == 'InitialContextSetupRequest':
            session_dict = eMENU.print_log(session_dict, "S1AP: InitialContextSetupRequest received")
            answer_list, session_dict= ProcessInitialContextSetupRequest(protocolIEs_list, session_dict)
            for answer in answer_list:
                if answer != None:
                    PDU.set_val(answer)
                    message = PDU.to_aper()               
                    bytes_sent = client.send(message)                     
                
        elif procedure == 'UEContextReleaseCommand':
            session_dict = eMENU.print_log(session_dict, "S1AP: UEContextReleaseCommand received")
            answer, session_dict = ProcessUEContextReleaseCommand(pdu_dict,protocolIEs_list, session_dict)
            if answer != None:
                PDU.set_val(answer)
                message = PDU.to_aper()               
                bytes_sent = client.send(message)    
                
        elif procedure == 'Paging':   
            if session_dict['PROCESS-PAGING'] == True:        
                session_dict = eMENU.print_log(session_dict, "S1AP: Paging received")
                answer, session_dict = ProcessPaging(protocolIEs_list, session_dict)
                if answer != None:
                    PDU.set_val(answer)
                    message = PDU.to_aper()               
                    bytes_sent = client.send(message) 

        elif procedure == 'E-RABSetupRequest':
            session_dict = eMENU.print_log(session_dict, "S1AP: ERABSetupRequest received")            
            answer_list, session_dict = ProcessERABSetupRequest(protocolIEs_list, session_dict)
            for answer in answer_list:
                if answer != None:
                    PDU.set_val(answer)
                    message = PDU.to_aper()               
                    bytes_sent = client.send(message)                           

        elif procedure == 'E-RABReleaseCommand':
            session_dict = eMENU.print_log(session_dict, "S1AP: ERABReleaseCommand received")            
            answer_list, session_dict = ProcessERABReleaseCommand(protocolIEs_list, session_dict)
            for answer in answer_list:
                if answer != None:
                    PDU.set_val(answer)
                    message = PDU.to_aper()               
                    bytes_sent = client.send(message)                 
  
  
        elif procedure == 'LocationReportingControl':
            session_dict = eMENU.print_log(session_dict, "S1AP: LocationReportingControl received")            
            answer, session_dict = ProcessLocationReportingControl(protocolIEs_list, session_dict)
            if answer != None:
                PDU.set_val(answer)
                message = PDU.to_aper()               
                bytes_sent = client.send(message)           

        elif procedure == 'UEContextModificationRequest':
            session_dict = eMENU.print_log(session_dict, "S1AP: UEContextModificationRequest received") 
            answer_list, session_dict = ProcessUEContextModificationRequest(protocolIEs_list, session_dict)
            for answer in answer_list:
                if answer != None:
                    PDU.set_val(answer)
                    message = PDU.to_aper()               
                    bytes_sent = client.send(message)               


        else:
            session_dict = eMENU.print_log(session_dict, "S1AP: " + procedure + " received") 
             
    elif type == 'successfulOutcome':
        procedure, protocolIEs_list = pdu_dict['value'][0], pdu_dict['value'][1]['protocolIEs']
        if procedure == "S1SetupResponse":
            session_dict = eMENU.print_log(session_dict, "S1AP: S1SetupResponse received")
            session_dict = S1SetupResponseProcessing(protocolIEs_list, session_dict)
        
        elif procedure == "ResetAcknowledge":
            session_dict = eMENU.print_log(session_dict, "S1AP: ResetAcknowledge received")
        else:
            session_dict = eMENU.print_log(session_dict, "S1AP: " + procedure + " received") 
    elif type == 'unsuccessfulOutcome':
        
        exit(1)



    return PDU, client, session_dict


    
######################################################################################################################################
######################################################################################################################################
#
#    G T P - U Procedures
#
######################################################################################################################################

def open_tun(n):
    n = int(n)
    TUNSETIFF = 0x400454ca
    IFF_TUN   = 0x0001
    IFF_TAP   = 0x0002
    IFF_NO_PI = 0x1000 # No Packet Information - to avoid 4 extra bytes

    TUNMODE = IFF_TUN | IFF_NO_PI
    MODE = 0
    DEBUG = 0
    if sys.platform == "linux" or sys.platform == "linux2":
        f = os.open("/dev/net/tun", os.O_RDWR)
        ifs = fcntl.ioctl(f, TUNSETIFF, struct.pack("16sH", bytes("tun%d" % n, "utf-8"), TUNMODE))
        #ifname = ifs[:16].strip("\x00")
        subprocess.call("ifconfig tun%d up" % n, shell=True)
    elif sys.platform == "darwin":
        f = os.open("/dev/tun" + str(n), os.O_RDWR)
        subprocess.call("ifconfig tun" + str(n) + " up", shell=True)
	   
    return f

def gtp_u_header(teid, length):
    gtp_flags = b'\x30'
    gtp_message_type = b'\xff'
    gtp_length = struct.pack("!H", length)
    gtp_teid = teid
    fin=gtp_flags + gtp_message_type + gtp_length + gtp_teid
    return gtp_flags + gtp_message_type + gtp_length + gtp_teid

def encapsulate_gtp_u(ul_socket,ul_gtp):  
    s_gtpu=ul_socket
    while True:
        try:
            tap_packet = ul_gtp.recvfrom(5000)
            if tap_packet[0][26:30] in gtp_dict:
                teid=gtp_dict[tap_packet[0][26:30]][0]
                s_gtpu.sendto(gtp_u_header(teid, len(tap_packet[0][14:])) + tap_packet[0][14:], (socket.inet_ntoa(gtp_dict[tap_packet[0][26:30]][1]), 2152))
        except:
            pass           

def decapsulate_gtp_u(ul_socket,to_ue):

    s_gtpu = ul_socket
    ethHeader=Ether(src=netifaces.ifaddresses('brlo')[netifaces.AF_LINK][0]['addr'],dst="ff:ff:ff:ff:ff:ff",type=0x0800)
    
    while True: 

        gtp_packet, gtp_address = s_gtpu.recvfrom(5000)
        if gtp_packet[0:2] == b'\x30\xff':
            #raw_packet=Ether(gtp_packet[8:])
            pkt=ethHeader/gtp_packet[8:]
            sendp(pkt,iface="brlo",verbose=0)
                             
        elif gtp_packet[1:2] == b'\x01':
            gtp_echo_response = bytearray(gtp_packet) + b'\x0e\x00'
            gtp_echo_response[1] = 2
            gtp_echo_response[3] += 2
            s_gtpu.sendto(gtp_echo_response, (socket.inet_ntoa(session_dict['SGW-GTP-ADDRESS'][-1]), 2152))


                
# User Object class
class UserDict(dict):
    def __init__(self, *arg, **kw):
        super(UserDict, self).__init__(*arg, **kw)
        self.setdefault('OP',None)
        self.setdefault('ENB-UE-S1AP-ID',1000)
        self.setdefault('APN',"internet")
        self.setdefault('ENB-CELLID',1000000)
        self.setdefault('ENB-TAC1',int(73).to_bytes(2, byteorder='big'))
        self.setdefault('ENB-TAC2',int(74).to_bytes(2, byteorder='big'))
        self.setdefault('LOCAL_KEYS',False)
        self.setdefault('SERIAL-INTERFACE','/dev/ttyUSB2')
        self.setdefault('LOCAL_MILENAGE',True)
        self.setdefault('ENB-NAME','eNB')
        self.setdefault('ENB-PLMN',return_plmn_s1ap(self.get('PLMN')))
        self.setdefault('PDN-ADDRESS-IPV6',None)
        self.setdefault('ENB-TAC', self.get('ENB-TAC1'))
        self.setdefault('ENB-TAC-NBIOT',b'\x00\x02')     
        self.setdefault('ENB-ID',1)
        self.setdefault('UP-COUNT',-1)    
        self.setdefault('DOWN-COUNT',-1)
        self.setdefault('ENC-ALG',0)
        self.setdefault('INT-ALG',0) 
        self.setdefault('ENC-KEY',None)
        self.setdefault('INT-KEY',None)  
        self.setdefault('NAS-SMS-MT',None)
        self.setdefault('S-TMSI',None)
        self.setdefault('TMSI',None)
        self.setdefault('LAI',None)
        self.setdefault('CPSR-TYPE',0)
        self.setdefault('S1-TYPE',"4G")
        self.setdefault('MOBILE-IDENTITY-TYPE',"IMSI") 
        self.setdefault('SESSION-SESSION-TYPE',"NONE")
        self.setdefault('SESSION-TYPE',"4G")
        self.setdefault('SESSION-TYPE-TUN',1)
        self.setdefault('PDP-TYPE',1)
        self.setdefault('ATTACH-PDN',None)
        self.setdefault('ATTACH-TYPE',1)
        self.setdefault('TAU-TYPE',0)
        self.setdefault('SMS-UPDATE-TYPE',False)
        self.setdefault('NBIOT-SESSION-TYPE',"NONE")
        self.setdefault('CPSR-TYPE',0)
        self.setdefault('UECONTEXTRELEASE-CSFB',False)
        self.setdefault('PROCESS-PAGING',True)
        self.setdefault('PCSCF-RESTORATION',False)
        self.setdefault('DNS-REQ',True)
        self.setdefault('NAS-KEY-SET-IDENTIFIER',0)
        self.setdefault('LOG',[])
        self.setdefault('NON-IP-PACKET',1)
        self.setdefault('NON-IP-PACKETS',[NON_IP_PACKET_1, NON_IP_PACKET_2, NON_IP_PACKET_3, NON_IP_PACKET_4])
        self.setdefault('DATA-INT',"ens40")
#        self.setdefault('MOBILE-IDENTITY',self.get('ENCODED-IMSI'))
#######################(###############################################################################################################
#######################(###############################################################################################################


######################################################################################################################################
######################################################################################################################################
if __name__ == "__main__":
    os.system("ip netns show |awk {'print $1'}|xargs -I {} ip netns del {}")
    ue_eth=[(f"veth{n}",f"neth{n}") for n in range(1000)]
    upteid=1
    bridge_name="brlo"  
    user_dict = {}
    gtp_dict = {}
    enb_s1ap_id = 1
    parser = OptionParser()
    parser.add_option("-i", "--ip", dest="eNB_ip", help="eNB Local IP Address")
    parser.add_option("-m", "--mme", dest="mme_ip", help="MME IP Address")
    (options, args) = parser.parse_args()
    options.serial_interface="/dev/ttyUSB2"
    sys_queue="/foo"
    tmp_file="/tmp/foo"
    bridge_up()
    server_address = (options.mme_ip, 36412)

    #socket options
    client = socket.socket(socket.AF_INET,socket.SOCK_STREAM,socket.IPPROTO_SCTP)
    client.settimeout(5)
    try:
       client.bind((options.eNB_ip, 0))
    except Exception as e:
       logging.info(f"enb ip error {e} {options.eNB_ip}")
       sys.exit()

    sctp_default_send_param = bytearray(client.getsockopt(132,10,32))
    sctp_default_send_param[11]= 18
    client.setsockopt(132, 10, sctp_default_send_param)
        
    #variables initialization 
    PDU = S1AP.S1AP_PDU_Descriptions.S1AP_PDU
    #################################################
    #################################################
    #################################################
    
    # settting initial settings
    #session_dict = session_dict_initialization(session_dict)
    #session_dict['ENB-GTP-ADDRESS-INT'] = ip2int(options.eNB_ip)
    #session_dict['ENB-GTP-ADDRESS'] = socket.inet_aton(options.eNB_ip)
    session_dict=UserDict()
    s_gtpu = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s_gtpu.bind((options.eNB_ip, 2152))
    pipe_in_gtpu_encapsulate, pipe_out_gtpu_encapsulate = os.pipe()
    pipe_in_gtpu_decapsulate, pipe_out_gtpu_decapsulate = os.pipe()
    session_dict['PIPE-OUT-GTPU-ENCAPSULATE'] = pipe_out_gtpu_encapsulate
    session_dict['PIPE-OUT-GTPU-DECAPSULATE'] = pipe_out_gtpu_decapsulate
    session_dict['GTP-U'] = b'\x02' # inactive
    ul_gtp= socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    ul_gtp.bind((bridge_name,0)) 
    worker1 = Thread(target = encapsulate_gtp_u, args = (s_gtpu,ul_gtp,))
    worker2 = Thread(target = decapsulate_gtp_u, args = (s_gtpu,ul_gtp,))
    worker1.setDaemon(True)
    worker2.setDaemon(True)
    worker1.start()
    worker2.start()

    try:
        client.connect(server_address)
    except Exception as e:
        logging.info(f"Unable to connect to edge error {e} {server_address}")
        os.system(f"echo FAILED>/var/log/sim/enb_status")
        sys.exit()

    q = posixmq.Queue(sys_queue)
    while q.qsize()>0:
        q.get()
    #socket_list = [sys.stdin ,client, dev_nbiot]
    send_fd= open(tmp_file, 'w')
    socket_list = [send_fd,client]
    imeisv=1000000000000000
    os.system(f"echo CONNECTED>/var/log/sim/enb_status")
    while True:
        read_sockets, write_sockets, error_sockets = select.select(socket_list, [], [])
        for sock in read_sockets:
            if sock == client:
                buffer = client.recv(4096)
                PDU.from_aper(buffer)
                (type, pdu_dict) = PDU()
                for initial_dic in pdu_dict['value']:
                    if 'protocolIEs' in initial_dic:
                        for final_dic in  initial_dic['protocolIEs']:
                            if 'id' in final_dic and final_dic['id'] == 8:
                                for user_key, user_value in user_dict.items():
                                    if final_dic['value'][1] == user_value['ENB-UE-S1AP-ID']:
                                        session_dict=user_dict[user_key]
                                        break
                if  pdu_dict['value'][0] == 'Paging':                   
                    for i in pdu_dict['value'][1]['protocolIEs']:
                        if i['id'] == 43:
                            if i['value'][1][0] == 's-TMSI':
                                MME_CODE = i['value'][1][1]['mMEC']
                                M_TMSI = i['value'][1][1]['m-TMSI']
                                for user_key, user_value in user_dict.items():
                                    if user_value['S-TMSI'] == MME_CODE + M_TMSI:
                                        session_dict=user_dict[user_key]

                PDU, client, session_dict = ProcessS1AP(type, pdu_dict, client, session_dict)
            elif sock == send_fd:
                  if q.qsize()>0: 
                    queue_msg=q.get()
                    if queue_msg['procedure']=='s1-setup':
                        session_dict=UserDict()
                        if 'mcc' in queue_msg and 'mnc' in queue_msg:
                            session_dict['PLMN'] = f"{queue_msg['mcc']}{queue_msg['mnc']}"
                        else:
                            session_dict['PLMN'] = '111111'
                        session_dict['ENB-PLMN']=return_plmn_s1ap(session_dict['PLMN']) 
                        if 'enb_id' in queue_msg:
                            session_dict['ENB-ID'] =int(queue_msg['enb_id'])
                        else:
                            session_dict['ENB-ID'] =100000
                        if 'tac1' in queue_msg:
                            session_dict['ENB-TAC1']=int(queue_msg['tac1']).to_bytes(2, byteorder='big')
                        else:
                            session_dict['ENB-TAC1']=int(queue_msg[73]).to_bytes(2, byteorder='big')
                        if 'tac2' in queue_msg:
                            session_dict['ENB-TAC2']=int(queue_msg['tac2']).to_bytes(2, byteorder='big')
                        else:
                            session_dict['ENB-TAC2']=int(queue_msg[74]).to_bytes(2, byteorder='big')
                    else:
                        if queue_msg['imsi'] in user_dict:
                                logging.info(f'imsi {queue_msg} found in object')
                                session_dict = user_dict[queue_msg['imsi']]
                                try:
                                    del gtp_dict[hexlify(socket.inet_ntoa(session_dict['PDN-ADDRESS-IPV4']))]
                                    ue_eth_pair(session_dict['UE-NAMESPACE'])
                                except:
                                    pass
                                if 'auth-error' in queue_msg:
                                    if queue_msg['auth-error']:
                                        session_dict['AUTH-ERROR']=True
                                else:
                                    session_dict['AUTH-ERROR']=False
                        else:
                            if set(('imsi', 'ki','opc','mcc','mnc')).issubset(queue_msg):
                                imeisv += 1
                                user_dict[queue_msg['imsi']]=UserDict()
                                session_dict=user_dict[queue_msg['imsi']]
                                session_dict['MME-UE-S1AP-ID']=None
                                session_dict['IMSI']=queue_msg['imsi']
                                session_dict['KI']=unhexlify(queue_msg['ki'])
                                session_dict['OPC']=unhexlify(queue_msg['opc'])
                                session_dict['PLMN']= f"{queue_msg['mcc']}{queue_msg['mnc']}"
                                session_dict['ENB-PLMN']=return_plmn_s1ap(session_dict['PLMN'])
                                session_dict['IMEISV']= str(imeisv)
                                session_dict['STATE']=1
                                session_dict['PDN-ADDRESS-IPV4']=None
                                session_dict['PDN-ADDRESS']= []
                                session_dict['ENB-GTP-ADDRESS-INT']=''
                                session_dict['RAB-ID']=[]
                                session_dict['SGW-GTP-ADDRESS']=[]
                                session_dict['SGW-TEID']=[]
                                session_dict['EPS-BEARER-IDENTITY']=[]
                                session_dict['EPS-BEARER-TYPE']=[]  # default 0, dedicated 1
                                session_dict['EPS-BEARER-STATE']=[] # active 1, inactive 0
                                session_dict['EPS-BEARER-APN']=[]
                                session_dict['ENCODED-IMSI']=eNAS.encode_imsi(session_dict['IMSI'])
                                session_dict['MOBILE-IDENTITY']=session_dict['ENCODED-IMSI']
                                session_dict['ENCODED-IMEI']=eNAS.encode_imei(session_dict['IMEISV'])
                                session_dict['ENCODED-GUTI']=eNAS.encode_guti(int(session_dict['PLMN']),32769,1,12345678)
                                session_dict['KASME'] = b'kasme   kasme   kasme   kasme   '
                                session_dict['XRES'] = b'xresxres'
                                session_dict['NAS-KEY-EEA1']=return_key(session_dict['KASME'],1,'NAS-ENC')
                                session_dict['NAS-KEY-EEA2']=return_key(session_dict['KASME'],2,'NAS-ENC')
                                session_dict['NAS-KEY-EEA3']=return_key(session_dict['KASME'],3,'NAS-ENC')
                                session_dict['NAS-KEY-EIA1']=return_key(session_dict['KASME'],1,'NAS-INT')
                                session_dict['NAS-KEY-EIA2']=return_key(session_dict['KASME'],2,'NAS-INT')
                                session_dict['NAS-KEY-EIA3']=return_key(session_dict['KASME'],3,'NAS-INT')
                                session_dict['ENB-GTP-ADDRESS-INT']=ip2int(options.eNB_ip)
                                session_dict['PIPE-OUT-GTPU-ENCAPSULATE'] = pipe_out_gtpu_encapsulate
                                session_dict['PIPE-OUT-GTPU-DECAPSULATE'] = pipe_out_gtpu_decapsulate
                                session_dict['GTP-U'] = b'\x02'
                                session_dict['UL-TEID'] = None
                                session_dict['AUTH-ERROR']=False
                                session_dict['GTP-KEY']=None
                                session_dict['UE-NAMESPACE']=queue_msg['imsi']
                            else:
                                break
                    msg=queue_msg['procedure']
                    if 'IMSI' in session_dict:
                        logging.info(f"{msg} {session_dict['IMSI']} no if active user in tool {len(user_dict)} no of gtp tunnel {len(gtp_dict)}")
                    else:
                        logging.info(f"{msg} no if active user in tool {len(user_dict)} no of gtp tunnel {len(gtp_dict)}")
                    PDU, client, session_dict = eMENU.ProcessMenu(PDU, client, session_dict, msg)
    client.close()




