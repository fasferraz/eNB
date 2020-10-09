# Import the modules needed to run the script.
import sys, os
import datetime
from eNB_LOCAL import *
 
# Main definition - constants
menu_actions  = {}  


SEPARATOR_HORIZONTAL = '='
SEPARATOR_VERTICAL = '|'
MENU_WIDTH = 45
LOG_WIDTH = 110
LOG_SIZE = 100

 
# =======================
#     MENUS FUNCTIONS
# =======================
 
# Main menu

menu_list = [ '  0. Show current settings',     \
              '  1. Set S1 Setup type',         \
              '  2. Set Attach Mobile Identity',\
              '  3. Set Attach PDN',            \
              '  4. Set Session type',          \
              '  5. Set NBIOT PSM/eDRX',        \
              '  6. Set PDN type',              \
              '  7. Set CPSR type',             \
              '  8. Set Attach type',             \
              '  9. Set TAU type (for option 22)',             \
              ' 10. Set Process Paging',             \
              ' 11. Set SMS (AdditionalUpdateType)',             \
              ' 12. Set eNB-CellID',             \
              ' 13. Set P-CSCF Restoration Support',             \
              ' ',                              \
              ' 15. S1 Setup',          \
              ' 16. S1 Reset',          \
              ' ',                              \
              ' 20. Attach', \
              ' 21. Detach', \
              ' 22. TAU', \
              ' 23. TAU Periodic', \
              ' 24. Service Request',           \
              ' 25. Release UE Context',        \
              ' 26. Send SMS',        \
              ' 30. Control Plane Service Request',\
              ' 35. E-RAB ModificationIndication',\
              ' 36. Secondary RAT Data Usage Report',\
              ' ',                              \
              ' 40. PDN Connectivity',          \
              ' 41. PDN Disconnect',            \
              ' ',                              \
              ' 50. Activate GTP-U/IP over ControlPlane',            \
              ' 51. Deactivate GTP-U/IP over ControlPlane',          \
              ' ',                              \
              ' 99. Clear Log',                 \
              '  Q. Quit' ]  


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_menu(log):

    MENU_SIZE = len(menu_list) + 1 
    log = log[-MENU_SIZE+1:]
    os.system('clear')

    title = []
    title.append("                     _  _____                   __     __")
    title.append(bcolors.HEADER + "=============== " + bcolors.ENDC + "___ / |/ / _ )  ___ __ _  __ __/ /__ _/ /____  ____ ")
    title.append(bcolors.HEADER + "==============" + bcolors.ENDC + " / -_)    / _  | / -_)  ' \/ // / / _ `/ __/ _ \/ __/ ")
    title.append(bcolors.HEADER + "==============" + bcolors.ENDC +" \__/_/|_/____/  \__/_/_/_/\_,_/_/\_,_/\__/\___/_/   (by fasferraz@gmail.com  v1.0) ") 
   
    print(title[0])
    for i in range(1,len(title)):
        print(title[i] + bcolors.HEADER + SEPARATOR_HORIZONTAL*(12+MENU_WIDTH+LOG_WIDTH-len(title[i])) + bcolors.ENDC)

    
    print(bcolors.HEADER + SEPARATOR_HORIZONTAL*(3+ MENU_WIDTH + LOG_WIDTH) + bcolors.ENDC)
    print(bcolors.HEADER + SEPARATOR_VERTICAL + ' '*MENU_WIDTH + SEPARATOR_VERTICAL + ' '*LOG_WIDTH + SEPARATOR_VERTICAL + bcolors.ENDC)
    print(bcolors.HEADER + SEPARATOR_VERTICAL + bcolors.WARNING + bcolors.BOLD + '  Menu:' + ' '*(MENU_WIDTH-len('  Menu:')) + bcolors.HEADER + SEPARATOR_VERTICAL  + bcolors.WARNING + bcolors.BOLD + '  Log:' + ' '*(LOG_WIDTH-len('  Log:')) + bcolors.HEADER + SEPARATOR_VERTICAL + bcolors.ENDC)    
    print(bcolors.HEADER+ SEPARATOR_VERTICAL + ' '*MENU_WIDTH + SEPARATOR_VERTICAL + ' '*LOG_WIDTH + SEPARATOR_VERTICAL + bcolors.ENDC)    
    for i in range(MENU_SIZE):
        if i < len(menu_list) and i<len(log):
            print(bcolors.HEADER + SEPARATOR_VERTICAL + bcolors.OKGREEN + menu_list[i] + ' '*(MENU_WIDTH-len(menu_list[i])) + bcolors.HEADER + SEPARATOR_VERTICAL + bcolors.FAIL + log[i] + ' '*(LOG_WIDTH-len(log[i]))+ bcolors.HEADER + SEPARATOR_VERTICAL + bcolors.ENDC)
        elif i< len(menu_list):
            print(bcolors.HEADER + SEPARATOR_VERTICAL + bcolors.OKGREEN + menu_list[i] + ' '*(MENU_WIDTH-len(menu_list[i])) + bcolors.HEADER + SEPARATOR_VERTICAL + ' '*LOG_WIDTH + SEPARATOR_VERTICAL + bcolors.ENDC)
        elif i< len(log):
            print(bcolors.HEADER + SEPARATOR_VERTICAL + ' '*MENU_WIDTH + SEPARATOR_VERTICAL + bcolors.FAIL + log[i] + ' '*(LOG_WIDTH-len(log[i])) + bcolors.HEADER + SEPARATOR_VERTICAL + bcolors.ENDC)
        else:
            print(bcolors.HEADER+ SEPARATOR_VERTICAL + ' '*MENU_WIDTH + SEPARATOR_VERTICAL + ' '*LOG_WIDTH + SEPARATOR_VERTICAL + bcolors.ENDC)
    print(bcolors.HEADER + SEPARATOR_HORIZONTAL*(3+ MENU_WIDTH + LOG_WIDTH) + bcolors.ENDC) 
    print('\nOption: ')
        


def ProcessMenu(PDU, client, session_dict, msg):
    if msg == "Q\n" or msg == "q\n": 
        os.system('clear')
        exit(1)    

    elif msg == "0\n":
        session_dict = print_log(session_dict, "IMSI: " + session_dict['IMSI'])
        session_dict = print_log(session_dict, "S1 Setup type: " + session_dict['S1-TYPE'])
        session_dict = print_log(session_dict, "Attach Mobile Identity: " + session_dict['MOBILE-IDENTITY-TYPE'])
        if session_dict['ATTACH-PDN'] == 1:
            session_dict = print_log(session_dict, "Attach PDN: Internet")
        elif session_dict['ATTACH-PDN'] == None:
            session_dict = print_log(session_dict, "Attach PDN: Default")   
        session_dict = print_log(session_dict, "Session Type: " + session_dict['SESSION-TYPE'])    
        if session_dict['NBIOT-SESSION-TYPE'] == "NONE":
            session_dict = print_log(session_dict, "NBIOT PSM/eDRX: None") 
        elif session_dict['NBIOT-SESSION-TYPE'] == "PSM":
            session_dict = print_log(session_dict, "NBIOT PSM/eDRX: PSM Only")
        elif session_dict['NBIOT-SESSION-TYPE'] == "EDRX":
            session_dict = print_log(session_dict, "NBIOT PSM/eDRX: eDRX Only")
        elif session_dict['NBIOT-SESSION-TYPE'] == "BOTH":          
            session_dict = print_log(session_dict, "NBIOT PSM/eDRX: PSM + eDRX")       
        session_dict = print_log(session_dict, "PDP Type (1-> IPv4, 2-> IPv6, 3-> IPv4v6): " + str( session_dict['PDP-TYPE'])) 
        if session_dict['CPSR-TYPE'] == 0: # NO-RADIO-BEARER
            session_dict = print_log(session_dict, "CPSR Type: No Radio Bearer")
        elif session_dict['CPSR-TYPE'] == 8: # RADIO-BEARER
            session_dict = print_log(session_dict, "CPSR Type: Radio Bearer")
        if session_dict['ATTACH-TYPE'] == 2:
            session_dict = print_log(session_dict, "Attach Type: Combined EPS/IMSI Attach")
        elif session_dict['ATTACH-TYPE'] == 1:            
            session_dict = print_log(session_dict, "Attach Type: EPS Attach")        
        if session_dict['PROCESS-PAGING'] == False:
            session_dict = print_log(session_dict, "Process Paging: False")
        elif session_dict['PROCESS-PAGING'] == True:            
            session_dict = print_log(session_dict, "Process Paging: True")      
        if session_dict['TAU-TYPE'] == 1:
            session_dict = print_log(session_dict, "TAU Type: Combined TA/LA Updating")
        elif session_dict['TAU-TYPE'] == 2:            
            session_dict = print_log(session_dict, "TAU Type: Combined TA/LA Updating with IMSI Attach")
        elif session_dict['TAU-TYPE'] == 0:            
            session_dict = print_log(session_dict, "TAU Type: TA Updating")
        if session_dict['SMS-UPDATE-TYPE'] == False:
            session_dict = print_log(session_dict, "AdditionalUPdateType: SMS Only: False")
        elif session_dict['SMS-UPDATE-TYPE'] == True:            
            session_dict = print_log(session_dict, "AdditionalUPdateType: SMS Only: True") 
            
            
    elif msg == "1\n":
        if session_dict['S1-TYPE'] == "4G":
            session_dict['S1-TYPE'] = "NBIOT"
            session_dict = print_log(session_dict, "S1 Setup type: NBIOT")
        elif session_dict['S1-TYPE'] == "NBIOT":
            session_dict['S1-TYPE'] = "BOTH"
            session_dict = print_log(session_dict, "S1 Setup type: BOTH")
        elif session_dict['S1-TYPE'] == "BOTH":
            session_dict['S1-TYPE'] = "4G"
            session_dict = print_log(session_dict, "S1 Setup type: 4G")            
        
    elif msg == "2\n":
        if session_dict['MOBILE-IDENTITY-TYPE'] == "IMSI":
            session_dict['MOBILE-IDENTITY-TYPE'] = "GUTI"
            session_dict['MOBILE-IDENTITY'] = session_dict['ENCODED-GUTI']
            session_dict = print_log(session_dict, "Attach Mobile Identity: GUTI")
        elif session_dict['MOBILE-IDENTITY-TYPE'] == "GUTI":
            session_dict['MOBILE-IDENTITY-TYPE'] = "IMSI"
            session_dict['MOBILE-IDENTITY'] = session_dict['ENCODED-IMSI']     
            session_dict = print_log(session_dict, "Attach Mobile Identity: IMSI")            

    elif msg == "3\n": #attach type, default or with apn
        if session_dict['ATTACH-PDN'] == None:
            session_dict['ATTACH-PDN'] = 1
            session_dict = print_log(session_dict, "Attach PDN: Internet")
        elif session_dict['ATTACH-PDN'] == 1:
            session_dict['ATTACH-PDN'] = None
            session_dict = print_log(session_dict, "Attach PDN: Default")
    
    elif msg == "4\n":
        if session_dict['SESSION-TYPE'] == "4G":
            session_dict['SESSION-TYPE'] = "NBIOT"
            session_dict['SESSION-TYPE-TUN'] = 2
            session_dict['SESSION-SESSION-TYPE'] = session_dict['NBIOT-SESSION-TYPE']
            session_dict = print_log(session_dict, "Session Type: NBIOT")
        elif session_dict['SESSION-TYPE'] == "NBIOT":
            session_dict['SESSION-TYPE'] = "5G"
            session_dict['SESSION-TYPE-TUN'] = 1
            session_dict['SESSION-SESSION-TYPE'] = None
            session_dict = print_log(session_dict, "Session Type: 5G")        
        elif session_dict['SESSION-TYPE'] == "5G":
            session_dict['SESSION-TYPE'] = "4G"
            session_dict['SESSION-TYPE-TUN'] = 1
            session_dict['SESSION-SESSION-TYPE'] = None
            session_dict = print_log(session_dict, "Session Type: 4G")
    
    elif msg == "5\n":
        if session_dict['NBIOT-SESSION-TYPE'] == "NONE":
            session_dict['NBIOT-SESSION-TYPE'] = "PSM"
            session_dict = print_log(session_dict, "NBIOT PSM/eDRX: PSM Only")
            if session_dict['SESSION-TYPE'] == "NBIOT":
                session_dict['SESSION-SESSION-TYPE'] = session_dict['NBIOT-SESSION-TYPE']
        elif session_dict['NBIOT-SESSION-TYPE'] == "PSM":
            session_dict['NBIOT-SESSION-TYPE'] = "EDRX"
            session_dict = print_log(session_dict, "NBIOT PSM/eDRX: eDRX Only")
            if session_dict['SESSION-TYPE'] == "NBIOT":
                session_dict['SESSION-SESSION-TYPE'] = session_dict['NBIOT-SESSION-TYPE']
        elif session_dict['NBIOT-SESSION-TYPE'] == "EDRX":
            session_dict['NBIOT-SESSION-TYPE'] = "BOTH"
            session_dict = print_log(session_dict, "NBIOT PSM/eDRX: PSM + eDRX")
            if session_dict['SESSION-TYPE'] == "NBIOT":
                session_dict['SESSION-SESSION-TYPE'] = session_dict['NBIOT-SESSION-TYPE']
        elif session_dict['NBIOT-SESSION-TYPE'] == "BOTH":
            session_dict['NBIOT-SESSION-TYPE'] = "NONE"            
            session_dict = print_log(session_dict, "NBIOT PSM/eDRX: None")
            if session_dict['SESSION-TYPE'] == "NBIOT":
                session_dict['SESSION-SESSION-TYPE'] = session_dict['NBIOT-SESSION-TYPE']

    elif msg == "6\n":
        if session_dict['PDP-TYPE'] == 3:
            session_dict['PDP-TYPE'] = 1
        
        else:
            session_dict['PDP-TYPE'] += 1
        session_dict = print_log(session_dict, "PDP Type (1-> IPv4, 2-> IPv6, 3-> IPv4v6): " + str( session_dict['PDP-TYPE']))          
  
    elif msg == "7\n":
        if session_dict['CPSR-TYPE'] == 0: # NO-RADIO-BEARER
            session_dict['CPSR-TYPE'] = 8 # RADIO-BEARER
            session_dict = print_log(session_dict, "CPSR Type: Radio Bearer")
        elif session_dict['CPSR-TYPE'] == 8: # RADIO-BEARER
            session_dict['CPSR-TYPE'] = 0 # NO-RADIO-BEARER
            session_dict = print_log(session_dict, "CPSR Type: No Radio Bearer")
           
    elif msg == "8\n":
        if session_dict['ATTACH-TYPE'] == 1:
            session_dict['ATTACH-TYPE'] = 2
            session_dict = print_log(session_dict, "Attach Type: Combined EPS/IMSI Attach")
        elif session_dict['ATTACH-TYPE'] == 2:            
            session_dict['ATTACH-TYPE'] = 1
            session_dict = print_log(session_dict, "Attach Type: EPS Attach")

    elif msg == "9\n":
        if session_dict['TAU-TYPE'] == 0:
            session_dict['TAU-TYPE'] = 1
            session_dict = print_log(session_dict, "TAU Type: Combined TA/LA Updating")
        elif session_dict['TAU-TYPE'] == 1:            
            session_dict['TAU-TYPE'] = 2
            session_dict = print_log(session_dict, "TAU Type: Combined TA/LA Updating with IMSI Attach")
        elif session_dict['TAU-TYPE'] == 2:            
            session_dict['TAU-TYPE'] = 0
            session_dict = print_log(session_dict, "TAU Type: TA Updating")
      
    elif msg == "10\n":
        if session_dict['PROCESS-PAGING'] == True:
            session_dict['PROCESS-PAGING'] = False
            session_dict = print_log(session_dict, "Process Paging: False")
        elif session_dict['PROCESS-PAGING'] == False:            
            session_dict['PROCESS-PAGING'] = True
            session_dict = print_log(session_dict, "Process Paging: True")

    elif msg == "11\n":
        if session_dict['SMS-UPDATE-TYPE'] == True:
            session_dict['SMS-UPDATE-TYPE'] = False
            session_dict = print_log(session_dict, "AdditionalUPdateType: SMS Only: False")
        elif session_dict['SMS-UPDATE-TYPE'] == False:            
            session_dict['SMS-UPDATE-TYPE'] = True
            session_dict = print_log(session_dict, "AdditionalUPdateType: SMS Only: True") 

    elif msg == "12\n":
        if session_dict['ENB-CELLID'] == 1000000:
            session_dict['ENB-CELLID'] = 2000000
            session_dict = print_log(session_dict, "eNB CellID: 2000000")
        elif session_dict['ENB-CELLID'] == 2000000:            
            session_dict['ENB-CELLID'] = 1000000
            session_dict = print_log(session_dict, "eNB CellID: 1000000")

    elif msg == "13\n":
        if session_dict['PCSCF-RESTORATION'] == True:
            session_dict['PCSCF-RESTORATION'] = False
            session_dict = print_log(session_dict, "P-CSCF Restoration Support: False")
        elif session_dict['PCSCF-RESTORATION'] == False:            
            session_dict['PCSCF-RESTORATION'] = True
            session_dict = print_log(session_dict, "P-CSCF Restoration Support: True") 
           
    elif msg == "15\n":
        PDU.set_val(S1SetupRequest(session_dict))
        message = PDU.to_aper()
        client = set_stream(client, 0)        
        bytes_sent = client.send(message)
  
    elif msg == "16\n":
    
        PDU.set_val(Reset(session_dict))
        message = PDU.to_aper()    
        client = set_stream(client, 0)
        bytes_sent = client.send(message)         

    elif msg == "20\n":
        if session_dict['STATE'] >0:      
            session_dict['NAS'] = nas_attach_request(
                (session_dict['SESSION-TYPE'],session_dict['SESSION-SESSION-TYPE']),
                session_dict['ATTACH-PDN'],
                session_dict['MOBILE-IDENTITY'],
                session_dict['PDP-TYPE'],
                session_dict['ATTACH-TYPE'],
                session_dict['TMSI'],
                session_dict['LAI'],
                session_dict['SMS-UPDATE-TYPE'],
                session_dict['PCSCF-RESTORATION']
            )
            session_dict['SQN'] = 0
            PDU.set_val(InitialUEMessage(session_dict))
            message = PDU.to_aper()
            client = set_stream(client, 1)
            bytes_sent = client.send(message)    



    elif msg == "21\n": 
        #start list
        if session_dict['STATE'] >1:
            session_dict = ProcessUplinkNAS('detach request', session_dict)
            if session_dict['MME-UE-S1AP-ID'] > 0:
                PDU.set_val(UplinkNASTransport(session_dict))
            else:
                PDU.set_val(InitialUEMessage(session_dict))
            message = PDU.to_aper()  
            client = set_stream(client, 1)
            bytes_sent = client.send(message)    
            
        else:
            session_dict = print_log(session_dict, "NAS: Unable to send DetachRequest. State = 0")

        
    elif msg == "22\n": 
        if session_dict['STATE'] >1: 
            session_dict = ProcessUplinkNAS('tracking area update request', session_dict)
            PDU.set_val(InitialUEMessage(session_dict))
            message = PDU.to_aper()  
            client = set_stream(client, 1)
            bytes_sent = client.send(message)

            
    elif msg == "23\n": 
        if session_dict['STATE'] >1: 
            session_dict = ProcessUplinkNAS('tracking area update request periodic', session_dict)
            PDU.set_val(InitialUEMessage(session_dict))
            message = PDU.to_aper()  
            client = set_stream(client, 1)
            bytes_sent = client.send(message)

        

    elif msg == "24\n":
        if session_dict['STATE'] >1: 
            session_dict = ProcessUplinkNAS('service request', session_dict)
            PDU.set_val(InitialUEMessage(session_dict))
            message = PDU.to_aper()    
            client = set_stream(client, 1)
            bytes_sent = client.send(message)                    

    elif msg == "25\n":               
        if session_dict['STATE'] >1: 
            PDU.set_val(UEContextReleaseRequest(session_dict))
            message = PDU.to_aper()    
            client = set_stream(client, 1)
            bytes_sent = client.send(message)

    elif msg == "26\n":               
        if session_dict['STATE'] >1: 
            session_dict = ProcessUplinkNAS('uplink nas transport', session_dict)
            PDU.set_val(UplinkNASTransport(session_dict))
            message = PDU.to_aper()    
            client = set_stream(client, 1)
            bytes_sent = client.send(message)

    elif msg == "30\n":
        if session_dict['STATE'] >1: 
            session_dict = ProcessUplinkNAS('control plane service request', session_dict)
            PDU.set_val(InitialUEMessage(session_dict))
            message = PDU.to_aper()  
            client = set_stream(client, 1)
            bytes_sent = client.send(message)  


    elif msg == "35\n":
        if session_dict['STATE'] >1 and session_dict['SESSION-TYPE'] == "5G": 

            PDU.set_val(ERABModificationIndication(session_dict))
            message = PDU.to_aper()  
            client = set_stream(client, 1)
            bytes_sent = client.send(message)  

    elif msg == "36\n":
        if session_dict['STATE'] >1 and session_dict['SESSION-TYPE'] == "5G": 

            PDU.set_val(SecondaryRATDataUsageReport(session_dict))
            message = PDU.to_aper()  
            client = set_stream(client, 1)
            bytes_sent = client.send(message)  


    elif msg == "40\n":
        if session_dict['STATE'] >1:
            if session_dict['MME-UE-S1AP-ID'] > 0:        
                session_dict = ProcessUplinkNAS('pdn connectivity request', session_dict)
                PDU.set_val(UplinkNASTransport(session_dict))
                message = PDU.to_aper()  
                client = set_stream(client, 1)
                bytes_sent = client.send(message)    
            else:
                session_dict = print_log(session_dict, "NAS: Unable to send PDNConnectivityRequest. No S1. Send ServiceRequest first.")               
        else:
            session_dict = print_log(session_dict, "NAS: Unable to send PDNConnectivityRequest. State < 2")


    elif msg == "41\n":
        if session_dict['STATE'] >1:    
            if session_dict['MME-UE-S1AP-ID'] > 0: 
                session_dict = ProcessUplinkNAS('pdn disconnect request', session_dict)
                PDU.set_val(UplinkNASTransport(session_dict))
                message = PDU.to_aper()  
                client = set_stream(client, 1)
                bytes_sent = client.send(message)    
            else:
                session_dict = print_log(session_dict, "NAS: Unable to send PDNDisconnectRequest. No S1. Send ServiceRequest first.")
        else:
            session_dict = print_log(session_dict, "NAS: Unable to send PDNDisconnectRequest. State < 2")            
            
    elif msg == "50\n":
        if session_dict['STATE'] > 1:
            if session_dict['GTP-U'] == b'\x02':
                session_dict['GTP-U'] = b'\x01' 
                if len(session_dict['SGW-GTP-ADDRESS']) > 0:
                    os.write(session_dict['PIPE-OUT-GTPU-ENCAPSULATE'],session_dict['GTP-U'] + session_dict['SGW-GTP-ADDRESS'][-1] + session_dict['SGW-TEID'][-1])
                    os.write(session_dict['PIPE-OUT-GTPU-DECAPSULATE'],session_dict['GTP-U'] + session_dict['SGW-GTP-ADDRESS'][-1] + b'\x00\x00\x00' + bytes([session_dict['RAB-ID'][-1]]))
                if session_dict['PDN-ADDRESS-IPV4'] is not None:                     
                    subprocess.call("route add -net 0.0.0.0/1 gw " + session_dict['PDN-ADDRESS-IPV4'], shell=True)    
                    subprocess.call("route add -net 128.0.0.0/1 gw " + session_dict['PDN-ADDRESS-IPV4'], shell=True)
                if session_dict['PDN-ADDRESS-IPV6'] is not None:
                    subprocess.call("route -A inet6 add ::/1 dev tun" + str(session_dict['SESSION-TYPE-TUN']) , shell=True) 
                    subprocess.call("route -A inet6 add 8000::/1 dev tun" + str(session_dict['SESSION-TYPE-TUN'])  , shell=True)
                if session_dict['GATEWAY'] is not None and len(session_dict['SGW-GTP-ADDRESS']) > 0:
                    subprocess.call("route add " + socket.inet_ntoa(session_dict['SGW-GTP-ADDRESS'][-1])  + "/32 gw " + session_dict['GATEWAY'], shell=True)
                session_dict = print_log(session_dict, "GTP-U/IP over ControlPlane: Activation")
            else:
                session_dict = print_log(session_dict, "GTP-U/IP over ControlPlane: Already activated.")
        else:
            session_dict = print_log(session_dict, "GTP-U: Unable to Activate. State < 2")
            
    elif msg == "51\n":
        if session_dict['GTP-U'] == b'\x01': 
            session_dict['GTP-U'] = b'\x02' 
            if len(session_dict['SGW-GTP-ADDRESS']) > 0:
                os.write(session_dict['PIPE-OUT-GTPU-ENCAPSULATE'],session_dict['GTP-U'] + session_dict['SGW-GTP-ADDRESS'][-1] + session_dict['SGW-TEID'][-1])
                os.write(session_dict['PIPE-OUT-GTPU-DECAPSULATE'],session_dict['GTP-U'] + session_dict['SGW-GTP-ADDRESS'][-1] + b'\x00\x00\x00' + bytes([session_dict['RAB-ID'][-1]]))
            if session_dict['PDN-ADDRESS-IPV4'] is not None:     
                subprocess.call("route del -net 0.0.0.0/1 gw " + session_dict['PDN-ADDRESS-IPV4'], shell=True)    
                subprocess.call("route del -net 128.0.0.0/1 gw " + session_dict['PDN-ADDRESS-IPV4'], shell=True)
            if session_dict['PDN-ADDRESS-IPV6'] is not None:
                subprocess.call("route -A inet6 del ::/1 dev tun" + str(session_dict['SESSION-TYPE-TUN']) , shell=True) 
                subprocess.call("route -A inet6 del 8000::/1 dev tun" + str(session_dict['SESSION-TYPE-TUN'])  , shell=True)    
            if session_dict['GATEWAY'] is not None and len(session_dict['SGW-GTP-ADDRESS']) > 0:
                subprocess.call("route del " + socket.inet_ntoa(session_dict['SGW-GTP-ADDRESS'][-1])  + "/32 gw " + session_dict['GATEWAY'], shell=True)
            session_dict = print_log(session_dict, "GTP-U/IP over ControlPlane: Desactivation")
        else:
            session_dict = print_log(session_dict, "GTP-U/IP over ControlPlane: Already inactive.")
    elif msg == "99\n":
        session_dict['LOG'] = []
        print_menu(session_dict['LOG'])
        
    
    else:
        print_menu(session_dict['LOG'])    

    return PDU, client, session_dict
    
    
    
def print_log(session_dict, log_message):
    data = '  ' + str(datetime.datetime.now())
    log_message = str(log_message)
    if len(data + ': ' + log_message) > LOG_WIDTH:
        step = LOG_WIDTH-3-len(data)
        for i in range(0,len(log_message),step):
            session_dict['LOG'].append(data +': ' + log_message[i:i+step])
    else:
        session_dict['LOG'].append(data +': ' + log_message)
        
    session_dict['LOG'] = session_dict['LOG'][-LOG_SIZE:]
    print_menu(session_dict['LOG'])
    
    return session_dict    

 