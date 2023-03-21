# Import the modules needed to run the script.
import sys, os
import datetime
from eNB_LOCAL import * 
import logging 
# Main definition - constants
menu_actions  = {}  

SEPARATOR_HORIZONTAL = '='
SEPARATOR_VERTICAL = '|'
MENU_WIDTH = 45
LOG_WIDTH = 110
LOG_SIZE = 100

os.system("mkdir -p /var/log/sim/")
logging.basicConfig(filename="/var/log/sim/tool.log",filemode='w',format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',datefmt='%Y-%m-%d %H:%M:%S',level=logging.DEBUG)
logger = logging.getLogger('edge_log')
logging.info(" ********************* tool started ***************")
# =======================
#     MENUS FUNCTIONS
# =======================
 
# Main menu
def dynamic_variable():
    global enb_s1ap_id
    enb_s1ap_id +=1
    if enb_s1ap_id == 10000:
        enb_s1ap_id = 1
    var_dic= {'enb_s1ap_id':enb_s1ap_id}
    return var_dic
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
              ' 12. Set eNB-CellID/TAC',             \
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
              ' 35. E-RAB ModificationIndication (5G)',\
              ' 36. Secondary RAT Data Usage Report (5G)',\
              ' ',                              \
              ' 40. PDN Connectivity',          \
              ' 41. PDN Disconnect',            \
              ' ',                              \
              ' 50. Activate GTP-U/IP over ControlPlane',            \
              ' 51. Deactivate GTP-U/IP over ControlPlane',          \
              ' ',                              \
              ' 60. Set Non-IP Packet to Send',            \
              ' 61. Send Non-IP Packet',          \
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
    pass
    #MENU_SIZE = len(menu_list) + 1 
    #log = log[-MENU_SIZE+1:]
    #os.system('clear')

    #title = []
    #title.append("                     _  _____                   __     __")
    #title.append(bcolors.HEADER + "=============== " + bcolors.ENDC + "___ / |/ / _ )  ___ __ _  __ __/ /__ _/ /____  ____ ")
    #title.append(bcolors.HEADER + "==============" + bcolors.ENDC + " / -_)    / _  | / -_)  ' \/ // / / _ `/ __/ _ \/ __/ ")
    #title.append(bcolors.HEADER + "==============" + bcolors.ENDC +" \__/_/|_/____/  \__/_/_/_/\_,_/_/\_,_/\__/\___/_/   (by fasferraz@gmail.com  v1.0) ") 
   
    #print(title[0])
    #for i in range(1,len(title)):
    #    print(title[i] + bcolors.HEADER + SEPARATOR_HORIZONTAL*(12+MENU_WIDTH+LOG_WIDTH-len(title[i])) + bcolors.ENDC)

    #
    #print(bcolors.HEADER + SEPARATOR_HORIZONTAL*(3+ MENU_WIDTH + LOG_WIDTH) + bcolors.ENDC)
    #print(bcolors.HEADER + SEPARATOR_VERTICAL + ' '*MENU_WIDTH + SEPARATOR_VERTICAL + ' '*LOG_WIDTH + SEPARATOR_VERTICAL + bcolors.ENDC)
    #print(bcolors.HEADER + SEPARATOR_VERTICAL + bcolors.WARNING + bcolors.BOLD + '  Menu:' + ' '*(MENU_WIDTH-len('  Menu:')) + bcolors.HEADER + SEPARATOR_VERTICAL  + bcolors.WARNING + bcolors.BOLD + '  Log:' + ' '*(LOG_WIDTH-len('  Log:')) + bcolors.HEADER + SEPARATOR_VERTICAL + bcolors.ENDC)    
    #print(bcolors.HEADER+ SEPARATOR_VERTICAL + ' '*MENU_WIDTH + SEPARATOR_VERTICAL + ' '*LOG_WIDTH + SEPARATOR_VERTICAL + bcolors.ENDC)    
    #for i in range(MENU_SIZE):
    #    if i < len(menu_list) and i<len(log):
    #        print(bcolors.HEADER + SEPARATOR_VERTICAL + bcolors.OKGREEN + menu_list[i] + ' '*(MENU_WIDTH-len(menu_list[i])) + bcolors.HEADER + SEPARATOR_VERTICAL + bcolors.FAIL + log[i] + ' '*(LOG_WIDTH-len(log[i]))+ bcolors.HEADER + SEPARATOR_VERTICAL + bcolors.ENDC)
    #    elif i< len(menu_list):
    #        print(bcolors.HEADER + SEPARATOR_VERTICAL + bcolors.OKGREEN + menu_list[i] + ' '*(MENU_WIDTH-len(menu_list[i])) + bcolors.HEADER + SEPARATOR_VERTICAL + ' '*LOG_WIDTH + SEPARATOR_VERTICAL + bcolors.ENDC)
    #    elif i< len(log):
    #        print(bcolors.HEADER + SEPARATOR_VERTICAL + ' '*MENU_WIDTH + SEPARATOR_VERTICAL + bcolors.FAIL + log[i] + ' '*(LOG_WIDTH-len(log[i])) + bcolors.HEADER + SEPARATOR_VERTICAL + bcolors.ENDC)
    #    else:
    #        print(bcolors.HEADER+ SEPARATOR_VERTICAL + ' '*MENU_WIDTH + SEPARATOR_VERTICAL + ' '*LOG_WIDTH + SEPARATOR_VERTICAL + bcolors.ENDC)
    #print(bcolors.HEADER + SEPARATOR_HORIZONTAL*(3+ MENU_WIDTH + LOG_WIDTH) + bcolors.ENDC) 
    #print('\nOption: ')
        


def ProcessMenu(PDU, client, session_dict, msg):
    global enb_s1ap_id
    if msg == "Q\n" or msg == "q\n": 
        os.system('clear')
        exit(1)    

    elif msg == "0":
        session_dict = print_log(session_dict, "IMSI: " + str(session_dict['IMSI']) + " / IMEI: " + str(session_dict['IMEISV']))
        session_dict = print_log(session_dict, "S1 Setup type: " + session_dict['S1-TYPE'])
        session_dict = print_log(session_dict, "PLMN: " + str(session_dict['PLMN']))
        session_dict = print_log(session_dict, "eNB TACs: [" + str(int.from_bytes(session_dict['ENB-TAC1'], byteorder='big')) + ", " + str(int.from_bytes(session_dict['ENB-TAC2'], byteorder='big')) + "], NB-IoT TAC: " + str(int.from_bytes(session_dict['ENB-TAC2'], byteorder='big')) + ", ENB-ID: " + str(session_dict['ENB-ID']) + " Cell-ID: " + str(session_dict['ENB-ID']))
        session_dict = print_log(session_dict, "Attach Mobile Identity: " + session_dict['MOBILE-IDENTITY-TYPE'])
        if session_dict['ATTACH-PDN'] == 1:
            session_dict = print_log(session_dict, "Attach PDN: Internet")
        elif session_dict['ATTACH-PDN'] == None:
            session_dict = print_log(session_dict, "Attach PDN: Default")
        session_dict = print_log(session_dict, "Session Type: " + session_dict['SESSION-TYPE'])    
        if session_dict['SESSION-SESSION-TYPE'] == "NONE":
            session_dict = print_log(session_dict, "PSM/eDRX: None") 
        elif session_dict['SESSION-SESSION-TYPE'] == "PSM":
            session_dict = print_log(session_dict, "PSM/eDRX: PSM Only")
        elif session_dict['SESSION-SESSION-TYPE'] == "EDRX":
            session_dict = print_log(session_dict, "PSM/eDRX: eDRX Only")
        elif session_dict['SESSION-SESSION-TYPE'] == "BOTH":          
            session_dict = print_log(session_dict, "PSM/eDRX: PSM + eDRX")       
        session_dict = print_log(session_dict, "PDP Type (1-> IPv4, 2-> IPv6, 3-> IPv4v6, 5-> Non-IP): " + str( session_dict['PDP-TYPE'])) 
        if session_dict['CPSR-TYPE'] == 0: # NO-RADIO-BEARER
            session_dict = print_log(session_dict, "CPSR Type: No Radio Bearer")
        elif session_dict['CPSR-TYPE'] == 8: # RADIO-BEARER
            session_dict = print_log(session_dict, "CPSR Type: Radio Bearer")
        if session_dict['ATTACH-TYPE'] == 2:
            session_dict = print_log(session_dict, "Attach Type: Combined EPS/IMSI Attach")
        elif session_dict['ATTACH-TYPE'] == 1:            
            session_dict = print_log(session_dict, "Attach Type: EPS Attach")        
        elif session_dict['ATTACH-TYPE'] == 6:            
            session_dict = print_log(session_dict, "Attach Type: EPS Emergency Attach")  
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
            
            
    elif msg == "1":
        if session_dict['S1-TYPE'] == "4G":
            session_dict['S1-TYPE'] = "NBIOT"
            session_dict = print_log(session_dict, "S1 Setup type: NBIOT")
        elif session_dict['S1-TYPE'] == "NBIOT":
            session_dict['S1-TYPE'] = "BOTH"
            session_dict = print_log(session_dict, "S1 Setup type: BOTH")
        elif session_dict['S1-TYPE'] == "BOTH":
            session_dict['S1-TYPE'] = "4G"
            session_dict = print_log(session_dict, "S1 Setup type: 4G")            
        
    elif msg == "2":
        if session_dict['MOBILE-IDENTITY-TYPE'] == "IMSI":
            session_dict['MOBILE-IDENTITY-TYPE'] = "GUTI"
            session_dict['MOBILE-IDENTITY'] = session_dict['ENCODED-GUTI']
            session_dict = print_log(session_dict, "Attach Mobile Identity: GUTI")
        elif session_dict['MOBILE-IDENTITY-TYPE'] == "GUTI":
            session_dict['MOBILE-IDENTITY-TYPE'] = "IMEI"
            session_dict['MOBILE-IDENTITY'] = session_dict['ENCODED-IMEI']     
            session_dict = print_log(session_dict, "Attach Mobile Identity: IMEI")            
        elif session_dict['MOBILE-IDENTITY-TYPE'] == "IMEI":
            session_dict['MOBILE-IDENTITY-TYPE'] = "IMSI"
            session_dict['MOBILE-IDENTITY'] = session_dict['ENCODED-IMSI']     
            session_dict = print_log(session_dict, "Attach Mobile Identity: IMSI")  



    elif msg == "3": #attach type, default or with apn
        if session_dict['ATTACH-PDN'] == None:
            session_dict['ATTACH-PDN'] = 1
            session_dict = print_log(session_dict, "Attach PDN: Internet")
        elif session_dict['ATTACH-PDN'] == 1:
            session_dict['ATTACH-PDN'] = None
            session_dict = print_log(session_dict, "Attach PDN: Default")
    
    elif msg == "4":
        if session_dict['SESSION-TYPE'] == "4G":
            session_dict['SESSION-TYPE'] = "NBIOT"
            session_dict['SESSION-TYPE-TUN'] = 2
            session_dict = print_log(session_dict, "Session Type: NBIOT")
        elif session_dict['SESSION-TYPE'] == "NBIOT":
            session_dict['SESSION-TYPE'] = "5G"
            session_dict['SESSION-TYPE-TUN'] = 1
            session_dict = print_log(session_dict, "Session Type: 5G")        
        elif session_dict['SESSION-TYPE'] == "5G":
            session_dict['SESSION-TYPE'] = "4G"
            session_dict['SESSION-TYPE-TUN'] = 1
            session_dict = print_log(session_dict, "Session Type: 4G")
    
    elif msg == "5":
        if session_dict['NBIOT-SESSION-TYPE'] == "NONE":
            session_dict['NBIOT-SESSION-TYPE'] = "PSM"
            session_dict = print_log(session_dict, "PSM/eDRX: PSM Only")
            session_dict['SESSION-SESSION-TYPE'] = session_dict['NBIOT-SESSION-TYPE']
        elif session_dict['NBIOT-SESSION-TYPE'] == "PSM":
            session_dict['NBIOT-SESSION-TYPE'] = "EDRX"
            session_dict = print_log(session_dict, "PSM/eDRX: eDRX Only")
            session_dict['SESSION-SESSION-TYPE'] = session_dict['NBIOT-SESSION-TYPE']
        elif session_dict['NBIOT-SESSION-TYPE'] == "EDRX":
            session_dict['NBIOT-SESSION-TYPE'] = "BOTH"
            session_dict = print_log(session_dict, "PSM/eDRX: PSM + eDRX")
            session_dict['SESSION-SESSION-TYPE'] = session_dict['NBIOT-SESSION-TYPE']
        elif session_dict['NBIOT-SESSION-TYPE'] == "BOTH":
            session_dict['NBIOT-SESSION-TYPE'] = "NONE"            
            session_dict = print_log(session_dict, "PSM/eDRX: None")
            session_dict['SESSION-SESSION-TYPE'] = session_dict['NBIOT-SESSION-TYPE']

    elif msg == "6":
        if session_dict['PDP-TYPE'] == 3:
            session_dict['PDP-TYPE'] = 5
        elif session_dict['PDP-TYPE'] == 5:
            session_dict['PDP-TYPE'] = 1        
        else:
            session_dict['PDP-TYPE'] += 1
        session_dict = print_log(session_dict, "PDP Type (1-> IPv4, 2-> IPv6, 3-> IPv4v6, 5-> Non-IP): " + str( session_dict['PDP-TYPE']))          
  
    elif msg == "7":
        if session_dict['CPSR-TYPE'] == 0: # NO-RADIO-BEARER
            session_dict['CPSR-TYPE'] = 8 # RADIO-BEARER
            session_dict = print_log(session_dict, "CPSR Type: Radio Bearer")
        elif session_dict['CPSR-TYPE'] == 8: # RADIO-BEARER
            session_dict['CPSR-TYPE'] = 0 # NO-RADIO-BEARER
            session_dict = print_log(session_dict, "CPSR Type: No Radio Bearer")
           
    elif msg == "8":
        if session_dict['ATTACH-TYPE'] == 1:
            session_dict['ATTACH-TYPE'] = 2
            session_dict = print_log(session_dict, "Attach Type: Combined EPS/IMSI Attach")
        elif session_dict['ATTACH-TYPE'] == 2:            
            session_dict['ATTACH-TYPE'] = 6
            session_dict = print_log(session_dict, "Attach Type: EPS Emergency Attach")
        elif session_dict['ATTACH-TYPE'] == 6:            
            session_dict['ATTACH-TYPE'] = 1
            session_dict = print_log(session_dict, "Attach Type: EPS Attach")


    elif msg == "9":
        if session_dict['TAU-TYPE'] == 0:
            session_dict['TAU-TYPE'] = 1
            session_dict = print_log(session_dict, "TAU Type: Combined TA/LA Updating")
        elif session_dict['TAU-TYPE'] == 1:            
            session_dict['TAU-TYPE'] = 2
            session_dict = print_log(session_dict, "TAU Type: Combined TA/LA Updating with IMSI Attach")
        elif session_dict['TAU-TYPE'] == 2:            
            session_dict['TAU-TYPE'] = 0
            session_dict = print_log(session_dict, "TAU Type: TA Updating")
      
    elif msg == "10":
        if session_dict['PROCESS-PAGING'] == True:
            session_dict['PROCESS-PAGING'] = False
            session_dict = print_log(session_dict, "Process Paging: False")
        elif session_dict['PROCESS-PAGING'] == False:            
            session_dict['PROCESS-PAGING'] = True
            session_dict = print_log(session_dict, "Process Paging: True")

    elif msg == "11":
        if session_dict['SMS-UPDATE-TYPE'] == True:
            session_dict['SMS-UPDATE-TYPE'] = False
            session_dict = print_log(session_dict, "AdditionalUPdateType: SMS Only: False")
        elif session_dict['SMS-UPDATE-TYPE'] == False:            
            session_dict['SMS-UPDATE-TYPE'] = True
            session_dict = print_log(session_dict, "AdditionalUPdateType: SMS Only: True") 

    elif msg == "12":
        if session_dict['ENB-CELLID'] == 1000000:
            session_dict['ENB-CELLID'] = 2000000
            session_dict['ENB-TAC'] = session_dict['ENB-TAC2']
            session_dict = print_log(session_dict, "eNB CellID: 2000000")
        elif session_dict['ENB-CELLID'] == 2000000:            
            session_dict['ENB-CELLID'] = 1000000
            session_dict['ENB-TAC'] = session_dict['ENB-TAC1']
            session_dict = print_log(session_dict, "eNB CellID: 1000000")

    elif msg == "13":
        if session_dict['PCSCF-RESTORATION'] == True:
            session_dict['PCSCF-RESTORATION'] = False
            session_dict = print_log(session_dict, "P-CSCF Restoration Support: False")
        elif session_dict['PCSCF-RESTORATION'] == False:            
            session_dict['PCSCF-RESTORATION'] = True
            session_dict = print_log(session_dict, "P-CSCF Restoration Support: True") 
           
    elif msg == "s1-setup":
        PDU.set_val(S1SetupRequest(session_dict))
        message = PDU.to_aper()
        client = set_stream(client, 0)        
        bytes_sent = client.send(message)
  
    elif msg == "s1-reset":
    
        PDU.set_val(Reset(session_dict))
        message = PDU.to_aper()    
        client = set_stream(client, 0)
        bytes_sent = client.send(message)         

    elif msg == "19":
        if session_dict['STATE'] >0:   

            session_dict['NAS-ENC'] = nas_attach_request(
                (session_dict['SESSION-TYPE'],session_dict['SESSION-SESSION-TYPE']),
                session_dict['ATTACH-PDN'],
                session_dict['MOBILE-IDENTITY'],
                session_dict['PDP-TYPE'],
                session_dict['ATTACH-TYPE'],
                session_dict['TMSI'],
                session_dict['LAI'],
                session_dict['SMS-UPDATE-TYPE'],
                session_dict['PCSCF-RESTORATION'],
                session_dict['NAS-KEY-SET-IDENTIFIER']
            )
            
            session_dict['UP-COUNT'] += 1 
            session_dict['DIR'] = 0            
            mac_bytes = nas_hash(session_dict)
            session_dict['NAS'] = nas_security_protected_nas_message(1,mac_bytes,bytes([session_dict['UP-COUNT']%256]),session_dict['NAS-ENC'])
            session_dict = print_log(session_dict, "NAS: sending AttachRequest")

            PDU.set_val(InitialUEMessage(session_dict))
            message = PDU.to_aper()
            client = set_stream(client, 1)
            bytes_sent = client.send(message) 


    elif msg == "attach":
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
            session_dict['MME-UE-S1AP-ID-OLD'] = session_dict['MME-UE-S1AP-ID']
            session_dict['ENB-UE-S1AP-ID-OLD'] = session_dict['ENB-UE-S1AP-ID']
            session_dict['ENB-UE-S1AP-ID'] = dynamic_variable()['enb_s1ap_id']
            PDU.set_val(InitialUEMessage(session_dict))
            message = PDU.to_aper()
            client = set_stream(client, 1)
            bytes_sent = client.send(message)    



    elif msg == "detach":
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

        
    elif msg == "tau":
        if session_dict['STATE'] >1: 
            session_dict['ENB-UE-S1AP-ID'] = dynamic_variable()['enb_s1ap_id']
            session_dict = ProcessUplinkNAS('tracking area update request', session_dict)
            PDU.set_val(InitialUEMessage(session_dict))
            message = PDU.to_aper()  
            client = set_stream(client, 1)
            bytes_sent = client.send(message)

            
    elif msg == "tau-p": 
        if session_dict['STATE'] >1:
            session_dict['ENB-UE-S1AP-ID'] = dynamic_variable()['enb_s1ap_id']
            session_dict = ProcessUplinkNAS('tracking area update request periodic', session_dict)
            PDU.set_val(InitialUEMessage(session_dict))
            message = PDU.to_aper()  
            client = set_stream(client, 1)
            bytes_sent = client.send(message)

        

    elif msg == "service-request":
        if session_dict['STATE'] >1:
            session_dict['ENB-UE-S1AP-ID'] = dynamic_variable()['enb_s1ap_id']
            session_dict = ProcessUplinkNAS('service request', session_dict)
            PDU.set_val(InitialUEMessage(session_dict))
            message = PDU.to_aper()    
            client = set_stream(client, 1)
            bytes_sent = client.send(message)                    

    elif msg == "idle":               
        if session_dict['STATE'] >1: 
            PDU.set_val(UEContextReleaseRequest(session_dict))
            message = PDU.to_aper()    
            client = set_stream(client, 1)
            bytes_sent = client.send(message)

    elif msg == "26":               
        if session_dict['STATE'] >1: 
            session_dict = ProcessUplinkNAS('uplink nas transport', session_dict)
            PDU.set_val(UplinkNASTransport(session_dict))
            message = PDU.to_aper()    
            client = set_stream(client, 1)
            bytes_sent = client.send(message)

    elif msg == "30":
        if session_dict['STATE'] >1: 
            session_dict = ProcessUplinkNAS('control plane service request', session_dict)
            PDU.set_val(InitialUEMessage(session_dict))
            message = PDU.to_aper()  
            client = set_stream(client, 1)
            bytes_sent = client.send(message)  


    elif msg == "35":
        if session_dict['STATE'] >1 and session_dict['SESSION-TYPE'] == "5G": 

            PDU.set_val(ERABModificationIndication(session_dict))
            message = PDU.to_aper()  
            client = set_stream(client, 1)
            bytes_sent = client.send(message)  

    elif msg == "36":
        if session_dict['STATE'] >1 and session_dict['SESSION-TYPE'] == "5G": 

            PDU.set_val(SecondaryRATDataUsageReport(session_dict))
            message = PDU.to_aper()  
            client = set_stream(client, 1)
            bytes_sent = client.send(message)  
  

    elif msg == "40":
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


    elif msg == "41":
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
    elif msg == "data":
        send_gtpu(session_dict)
    elif msg == "50":
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
            
    elif msg == "51":
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

    elif msg == "60":
        if session_dict['NON-IP-PACKET'] == 4:
            session_dict['NON-IP-PACKET'] = 1       
        else:
            session_dict['NON-IP-PACKET'] += 1
        session_dict = print_log(session_dict, "Non-IP Packet number: " + str(session_dict['NON-IP-PACKET']))          
  
    elif msg == "61":
        if session_dict['STATE'] > 1:
            session_dict['USER-DATA-CONTAINER'] = hex2bytes(session_dict['NON-IP-PACKETS'][session_dict['NON-IP-PACKET']-1])
            session_dict = ProcessUplinkNAS('esm data transport', session_dict)
                    
            if session_dict['MME-UE-S1AP-ID'] > 0: #s1 up -
                PDU.set_val(UplinkNASTransport(session_dict))
            else:
                session_dict = ProcessUplinkNAS('control plane service request with esm message container', session_dict)
                PDU.set_val(InitialUEMessage(session_dict))
            message = PDU.to_aper()  
            client = set_stream(client, 1)
            bytes_sent = client.send(message)


    elif msg == "99":
        session_dict['LOG'] = []
        print_menu(session_dict['LOG'])
        
    
    else:
        print_menu(session_dict['LOG'])    

    return PDU, client, session_dict
    
    
    
def print_log(session_dict, log_message):

    logging.info(f"{log_message}")
    
    return session_dict    

 
