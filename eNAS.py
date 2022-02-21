import struct
import socket
from binascii import hexlify, unhexlify

#BASE FUNCTION to be called from external 

#only used for downlink messages, so no SERVICE REQUEST message.
#input: nas message
def nas_decode(nas):
    nas_list = []
    if nas == None:
        return nas_list
        
    protocol_discriminator = nas[0] % 16
    nas_list.append(("protocol discriminator", protocol_discriminator))
    if protocol_discriminator == 7: # EMM
    
        security_header = nas[0] // 16
        nas_list.append(("security header", security_header))
        if security_header == 0: # plain nas
            nas_list.append(("message type", nas[1]))
            if len(nas)>2:
                emm_list = nas_decode_emm(nas[1], nas[2:])
                nas_list += emm_list
            #emm#

        

        else:
            nas_list.append(("message authentication code",nas[1:5]))
            nas_list.append(("sequence_number",nas[5]))
            nas_list.append(("nas message encrypted", nas[6:]))
                
    elif protocol_discriminator == 2: # ESM
        eps_bearer_identity = nas[0] // 16
        nas_list.append(("eps bearer identity", eps_bearer_identity))    
        nas_list.append(("procedure transaction identity", nas[1]))
        nas_list.append(("message type", nas[2]))
        if len(nas)>3:
            esm_list = nas_decode_esm(nas[2], nas[3:])
            nas_list += esm_list
            #esm#
        
    return nas_list

        
#------------------------------------#
#                                    #
#   E M M  -  P r o c e d u r e s    #
#                                    #
#------------------------------------#
             
#input: message_type and next bytes of nas with ies    
def nas_decode_emm(message_type, ies):
    ies_list = []
    if message_type == 66: # attach accept
        ies_list = nas_decode_emm_attach_accept(ies)
    elif message_type == 68: #attach reject
        ies_list = nas_decode_emm_attach_reject(ies)
    elif message_type == 69: #detach request
        ies_list = nas_decode_emm_detach_request(ies)
    elif message_type == 70: #detach accept
        ies_list = nas_decode_emm_detach_accept(ies)  
    elif message_type == 73: #tracking area update accept
        ies_list = nas_decode_emm_tracking_area_update_accept(ies)  
    elif message_type == 75: #tracking area update reject
        ies_list = nas_decode_emm_tracking_area_update_reject(ies)  
    elif message_type == 78: #service reject
        ies_list = nas_decode_emm_service_reject(ies)   
    elif message_type == 79: #service accept
        ies_list = nas_decode_emm_service_accept(ies)           
    elif message_type == 80: #guti reallocation coomand
        ies_list = nas_decode_emm_guti_reallocation_command(ies)
    elif message_type == 82: #authentication request
        ies_list = nas_decode_emm_authentication_request(ies)
    elif message_type == 84: #authentication reject
        ies_list = nas_decode_emm_authentication_reject(ies)
    elif message_type == 85: #identity request
        ies_list = nas_decode_emm_identity_request(ies)
    elif message_type == 93: #security mode command
        ies_list = nas_decode_emm_security_mode_command(ies)
    elif message_type == 96: #emm status
        ies_list = nas_decode_emm_emm_status(ies)
    elif message_type == 97: #emm information
        ies_list = nas_decode_emm_emm_information(ies)
    elif message_type == 98: #downlink nas transport
        ies_list = nas_decode_emm_downlink_nas_transport(ies)  
    elif message_type == 100: #cs service notification
        ies_list = nas_decode_emm_cs_service_notification(ies)          
    elif message_type == 104: #downlink generic nas transport
        ies_list = nas_decode_emm_downlink_generic_nas_transport(ies)          
    return ies_list
        
        
def nas_decode_emm_attach_accept(ies):
    ies_list = []
    ies_list.append(("eps attach result", ies[0] % 16))
    ies_list.append(("t3412 value", ies[1]))
    tai_list_length = ies[2]
    ies_list.append(("tai list", ies[3:3+tai_list_length]))
    pointer = 3 + tai_list_length
    esm_message_container_length = ies[pointer]*256+ies[pointer+1]
    esm_message_container = ies[pointer+2:pointer+2+esm_message_container_length]

    
    ies_list.append(("esm message container",nas_decode(esm_message_container)))
    pointer = pointer+2+esm_message_container_length
    
    exit_while = False
    
    while len(ies)>pointer and exit_while == False:
        if ies[pointer] == 0x50: # guti
            guti_length = ies[pointer + 1]
            guti = ies[pointer+2:pointer+2+guti_length]
            ies_list.append(("guti", guti))
            pointer = pointer+2+guti_length
        elif ies[pointer] == 0x13: #location area identification
            ies_list.append(("location area identification", ies[pointer+1:pointer+6]))
            pointer = pointer+6
        elif ies[pointer] == 0x23: #ms identity
            ms_identity_length = ies[pointer + 1]
            ms_identity = ies[pointer+2:pointer+2+ms_identity_length]
            ies_list.append(("ms identity", ms_identity))
            pointer = pointer+2+ms_identity_length

        elif ies[pointer] == 0x53: #emm cause
            ies_list.append(("emm cause", ies[pointer+1:pointer+1]))
            pointer = pointer+2
        elif ies[pointer] == 0x17: #t3402 value
            ies_list.append(("t3402 value", ies[pointer+1:pointer+1]))
            pointer = pointer+2
        elif ies[pointer] == 0x59: #t3423 value
            ies_list.append(("t3423 value", ies[pointer+1:pointer+1]))
            pointer = pointer+2            
        
        elif ies[pointer] == 0x4A: #equivalent plmns
            equivalent_plmns_length = ies[pointer + 1]
            equivalent_plmns = ies[pointer+2:pointer+2+equivalent_plmns_length]
            ies_list.append(("equivalent plmns", equivalent_plmns))
            pointer = pointer+2+equivalent_plmns_length        

        elif ies[pointer] == 0x34: #emergency number list
            emergency_number_list_length = ies[pointer + 1]
            emergency_number_list = ies[pointer+2:pointer+2+emergency_number_list_length]
            ies_list.append(("emergency number list", emergency_number_list))
            pointer = pointer+2+emergency_number_list_length          
        
        elif ies[pointer] == 0x64: #eps network feature support
            eps_network_feature_support_length = ies[pointer + 1]
            eps_network_feature_support = ies[pointer+2:pointer+2+eps_network_feature_support_length]
            ies_list.append(("eps network feature support", eps_network_feature_support))
            pointer = pointer+2+eps_network_feature_support_length          

        elif ies[pointer] == 0x5E: #t3412 extended value
            t3412_extended_value_length = ies[pointer + 1]
            t3412_extended_value = ies[pointer+2:pointer+2+t3412_extended_value_length]
            ies_list.append(("t3412 extended value", t3412_extended_value))
            pointer = pointer+2+t3412_extended_value_length             
        
        elif ies[pointer] // 16 == 0xF: # additional update result F-
            ies_list.append(("additional update result", ies[pointer]))
            pointer = pointer+1            

        elif ies[pointer] == 0x6A: #t3324_value
            t3324_value_length = ies[pointer + 1]
            t3324_value = ies[pointer+2:pointer+2+t3324_value_length]
            ies_list.append(("t3324 value", t3324_value))
            pointer = pointer+2+t3324_value_length  

        elif ies[pointer] == 0x6E: #extended_drx_parameters
            extended_drx_parameters_length = ies[pointer + 1]
            extended_drx_parameters = ies[pointer+2:pointer+2+extended_drx_parameters_length]
            ies_list.append(("extended drx parameters", extended_drx_parameters))
            pointer = pointer+2+extended_drx_parameters_length 

        elif ies[pointer] == 0x65: #dcn_id
            dcn_id_length = ies[pointer + 1]
            dcn_id = ies[pointer+2:pointer+2+dcn_id_length]
            ies_list.append(("dcn-id", dcn_id))
            pointer = pointer+2+dcn_id_length 

        elif ies[pointer] // 16 == 0xE: # sms_service_status
            ies_list.append(("sms service status", ies[pointer]))
            pointer = pointer+1   

        elif ies[pointer] // 16 == 0xD: # non_3gpp_nw_provided_policies
            ies_list.append(("non 3gpp nw provided policies", ies[pointer]))
            pointer = pointer+1   

        elif ies[pointer] == 0x6B: #t3448_value
            t3448_value_length = ies[pointer + 1]
            t3448_value = ies[pointer+2:pointer+2+t3448_value_length]
            ies_list.append(("t3448 value", t3448_value))
            pointer = pointer+2+t3448_value_length  

        elif ies[pointer] // 16 == 0xC: # network policy
            ies_list.append(("network policy", ies[pointer]))
            pointer = pointer+1  
        
        
        ######## LAST ONE TO EXIT WHILE LOOP ###
        else: # didn't find more IEs
            exit_while = True
    
    return ies_list
    
def nas_decode_emm_attach_reject(ies):
    ies_list = []
    ies_list.append(("emm cause", ies[0]))
    pointer = 1
    
    exit_while = False
    
    while len(ies)>pointer and exit_while == False:    
        if ies[pointer] == 0x78: # esm message container
            esm_message_container_length = ies[pointer+1]*256+ies[pointer+2]
            esm_message_container = ies[pointer+3:pointer+3+esm_message_container_length]
            ies_list.append(("esm message container",nas_decode(esm_message_container)))
            pointer = pointer+3+esm_message_container_length    

        elif ies[pointer] == 0x5F: #t3346 value
            t3346_value_length = ies[pointer + 1]
            t3346_value = ies[pointer+2:pointer+2+t3346_value_length]
            ies_list.append(("t3346 value", t3346_value))
            pointer = pointer+2+t3346_value_length  

        elif ies[pointer] == 0x16: #t3402 value
            t3402_value_length = ies[pointer + 1]
            t3402_value = ies[pointer+2:pointer+2+t3402_value_length]
            ies_list.append(("t3402 value", t3402_value))
            pointer = pointer+2+t3402_value_length  

        elif ies[pointer] // 16 == 0xA: # extended emm cause
            ies_list.append(("extended emm cause", ies[pointer]))
            pointer = pointer+1  

        ######## LAST ONE TO EXIT WHILE LOOP ###
        else: # didn't find more IEs
            exit_while = True   
    
    return ies_list

def nas_decode_emm_detach_request(ies):
    ies_list = []
    ies_list.append(("detach type", ies[0] % 16))
    pointer = 1
    
    exit_while = False
    
    while len(ies)>pointer and exit_while == False:
        if ies[pointer] == 0x53: #emm cause
            ies_list.append(("emm cause", ies[pointer+1:pointer+1]))
            pointer = pointer+2
            
        ######## LAST ONE TO EXIT WHILE LOOP ###
        else: # didn't find more IEs
            exit_while = True    
    
    return ies_list

def nas_decode_emm_detach_accept(ies):
    pass #done no IEI


def nas_decode_emm_tracking_area_update_accept(ies):
    ies_list = []
    ies_list.append(("eps update result", ies[0] % 16))
  
    pointer = 1
    
    exit_while = False
    
    while len(ies)>pointer and exit_while == False:
        if ies[pointer] == 0x5a: # t3412_value
            ies_list.append(("t3412 value", ies[pointer+1]))
            pointer = pointer+2
        elif ies[pointer] == 0x50: # guti
            guti_length = ies[pointer + 1]
            guti = ies[pointer+2:pointer+2+guti_length]
            ies_list.append(("guti", guti))
            pointer = pointer+2+guti_length
        elif ies[pointer] == 0x54: #tai list
            tai_list_length = ies[pointer + 1]
            tai_list = ies[pointer+2:pointer+2+tai_list_length]
            ies_list.append(("tai list", tai_list))
            pointer = pointer+2+tai_list_length              
        elif ies[pointer] == 0x57: #eps_bearer_context_status
            eps_bearer_context_status_length = ies[pointer + 1]
            eps_bearer_context_status = ies[pointer+2:pointer+2+eps_bearer_context_status_length]
            ies_list.append(("tai list", eps_bearer_context_status))
            pointer = pointer+2+eps_bearer_context_status_length   
        elif ies[pointer] == 0x13: #location area identification
            ies_list.append(("location area identification", ies[pointer+1:pointer+6]))
            pointer = pointer+6
        elif ies[pointer] == 0x23: #ms identity
            ms_identity_length = ies[pointer + 1]
            ms_identity = ies[pointer+2:pointer+2+ms_identity_length]
            ies_list.append(("ms identity", ms_identity))
            pointer = pointer+2+ms_identity_length

        elif ies[pointer] == 0x53: #emm cause
            ies_list.append(("emm cause", ies[pointer+1:pointer+1]))
            pointer = pointer+2
        elif ies[pointer] == 0x17: #t3402 value
            ies_list.append(("t3402 value", ies[pointer+1:pointer+1]))
            pointer = pointer+2
        elif ies[pointer] == 0x59: #t3423 value
            ies_list.append(("t3423 value", ies[pointer+1:pointer+1]))
            pointer = pointer+2            
        
        elif ies[pointer] == 0x4A: #equivalent plmns
            equivalent_plmns_length = ies[pointer + 1]
            equivalent_plmns = ies[pointer+2:pointer+2+equivalent_plmns_length]
            ies_list.append(("equivalent plmns", equivalent_plmns))
            pointer = pointer+2+equivalent_plmns_length        

        elif ies[pointer] == 0x34: #emergency number list
            emergency_number_list_length = ies[pointer + 1]
            emergency_number_list = ies[pointer+2:pointer+2+emergency_number_list_length]
            ies_list.append(("emergency number list", emergency_number_list))
            pointer = pointer+2+emergency_number_list_length          
        
        elif ies[pointer] == 0x64: #eps network feature support
            eps_network_feature_support_length = ies[pointer + 1]
            eps_network_feature_support = ies[pointer+2:pointer+2+eps_network_feature_support_length]
            ies_list.append(("eps network feature support", eps_network_feature_support))
            pointer = pointer+2+eps_network_feature_support_length          

        elif ies[pointer] == 0x5E: #t3412 extended value
            t3412_extended_value_length = ies[pointer + 1]
            t3412_extended_value = ies[pointer+2:pointer+2+t3412_extended_value_length]
            ies_list.append(("t3412 extended value", t3412_extended_value))
            pointer = pointer+2+t3412_extended_value_length             
        
        elif ies[pointer] // 16 == 0xF: # additional update result F-
            ies_list.append(("additional update result", ies[pointer]))
            pointer = pointer+1            

        elif ies[pointer] == 0x6A: #t3324_value
            t3324_value_length = ies[pointer + 1]
            t3324_value = ies[pointer+2:pointer+2+t3324_value_length]
            ies_list.append(("t3324 value", t3324_value))
            pointer = pointer+2+t3324_value_length  

        elif ies[pointer] == 0x6E: #extended_drx_parameters
            extended_drx_parameters_length = ies[pointer + 1]
            extended_drx_parameters = ies[pointer+2:pointer+2+extended_drx_parameters_length]
            ies_list.append(("extended drx parameters", extended_drx_parameters))
            pointer = pointer+2+extended_drx_parameters_length 

        elif ies[pointer] == 0x65: #dcn_id
            dcn_id_length = ies[pointer + 1]
            dcn_id = ies[pointer+2:pointer+2+dcn_id_length]
            ies_list.append(("dcn-id", dcn_id))
            pointer = pointer+2+dcn_id_length 

        elif ies[pointer] == 0x68: #header_compression_configuration_status
            header_compression_configuration_status_length = ies[pointer + 1]
            header_compression_configuration_status = ies[pointer+2:pointer+2+header_compression_configuration_status_length]
            ies_list.append(("header compression configuration status", header_compression_configuration_status))
            pointer = pointer+2+header_compression_configuration_status_length 

        elif ies[pointer] // 16 == 0xE: # sms_service_status
            ies_list.append(("sms service status", ies[pointer]))
            pointer = pointer+1   

        elif ies[pointer] // 16 == 0xD: # non_3gpp_nw_provided_policies
            ies_list.append(("non 3gpp nw provided policies", ies[pointer]))
            pointer = pointer+1   

        elif ies[pointer] == 0x6B: #t3448_value
            t3448_value_length = ies[pointer + 1]
            t3448_value = ies[pointer+2:pointer+2+t3448_value_length]
            ies_list.append(("t3448 value", t3448_value))
            pointer = pointer+2+t3448_value_length  

        elif ies[pointer] // 16 == 0xC: # network policy
            ies_list.append(("network policy", ies[pointer]))
            pointer = pointer+1  
        
        
        ######## LAST ONE TO EXIT WHILE LOOP ###
        else: # didn't find more IEs
            exit_while = True
    
    return ies_list

def nas_decode_emm_tracking_area_update_reject(ies):
    ies_list = []
    ies_list.append(("emm cause", ies[0]))
    pointer = 1
    
    exit_while = False
    
    while len(ies)>pointer and exit_while == False:    


        if ies[pointer] == 0x5F: #t3346 value
            t3346_value_length = ies[pointer + 1]
            t3346_value = ies[pointer+2:pointer+2+t3346_value_length]
            ies_list.append(("t3346 value", t3346_value))
            pointer = pointer+2+t3346_value_length  

        elif ies[pointer] // 16 == 0xA: # extended emm cause
            ies_list.append(("extended emm cause", ies[pointer]))
            pointer = pointer+1  

        ######## LAST ONE TO EXIT WHILE LOOP ###
        else: # didn't find more IEs
            exit_while = True   
    
    return ies_list


def nas_decode_emm_service_reject(ies):
    ies_list = []
    ies_list.append(("emm cause", ies[0]))
    pointer = 1
    
    exit_while = False
    
    while len(ies)>pointer and exit_while == False:    
        if ies[pointer] == 0x5B : # t3442
            ies_list.append(("t3442 value", ies[pointer+1:pointer+1]))
            pointer = pointer+2 

        elif ies[pointer] == 0x5F: #t3346 value
            t3346_value_length = ies[pointer + 1]
            t3346_value = ies[pointer+2:pointer+2+t3346_value_length]
            ies_list.append(("t3346 value", t3346_value))
            pointer = pointer+2+t3346_value_length  

        elif ies[pointer] == 0x6B: #t3448 value
            t3448_value_length = ies[pointer + 1]
            t3448_value = ies[pointer+2:pointer+2+t3448_value_length]
            ies_list.append(("t3448 value", t3448_value))
            pointer = pointer+2+t3448_value_length  

        ######## LAST ONE TO EXIT WHILE LOOP ###
        else: # didn't find more IEs
            exit_while = True   
    
    return ies_list



def nas_decode_emm_service_accept(ies):
    ies_list = []

    pointer = 0
    
    exit_while = False
    
    while len(ies)>pointer and exit_while == False:    
        if ies[pointer] == 0x5F: #t3346 value
            eps_bearer_context_status_length = ies[pointer + 1]
            eps_bearer_context_status = ies[pointer+2:pointer+2+eps_bearer_context_status_length]
            ies_list.append(("eps bearer context status", eps_bearer_context_status))
            pointer = pointer+2+eps_bearer_context_status_length  

        elif ies[pointer] == 0x6B: #t3448 value
            t3448_value_length = ies[pointer + 1]
            t3448_value = ies[pointer+2:pointer+2+t3448_value_length]
            ies_list.append(("t3448 value", t3448_value))
            pointer = pointer+2+t3448_value_length  

        ######## LAST ONE TO EXIT WHILE LOOP ###
        else: # didn't find more IEs
            exit_while = True   
    
    return ies_list

def nas_decode_emm_guti_reallocation_command(ies):
    ies_list = []
    ies_list.append(("guti", ies[0:0+12]))
    pointer = 1+12
    exit_while = False
    
    while len(ies)>pointer and exit_while == False:   
        if ies[pointer] == 0x54: #tai list
            tai_list_length = ies[pointer + 1]
            tai_list = ies[pointer+2:pointer+2+tai_list_length]
            ies_list.append(("tai list", tai_list))
            pointer = pointer+2+tai_list_length  
 
        elif ies[pointer] == 0x65: #dcn_id
            dcn_id_length = ies[pointer + 1]
            dcn_id = ies[pointer+2:pointer+2+dcn_id_length]
            ies_list.append(("dcn-id", dcn_id))
            pointer = pointer+2+dcn_id_length 


        ######## LAST ONE TO EXIT WHILE LOOP ###
        else: # didn't find more IEs
            exit_while = True  
    
    return ies_list

def nas_decode_emm_authentication_request(ies):
    ies_list = []
    ies_list.append(("nas key set identifier", ies[0] % 16))
    ies_list.append(("rand", ies[1:1+16]))
    pointer = 1+16
    autn_length = ies[pointer]
    ies_list.append(("autn", ies[pointer+1:pointer+1+autn_length]))
    
    return ies_list
    
def nas_decode_emm_authentication_reject(ies):
    pass #done no IEI

def nas_decode_emm_identity_request(ies):
    ies_list = []
    ies_list.append(("identity type", ies[0] % 16))
    
    return ies_list 

def nas_decode_emm_security_mode_command(ies):
    ies_list = []
    ies_list.append(("selected nas security algorithms", ies[0]))
    ies_list.append(("nas key set identifier", ies[1] % 16 ))
    pointer = 2
    replayed_ue_security_capabilities_length = ies[pointer]
    ies_list.append(("replayed ue security capabilities", ies[pointer+1:pointer+1+replayed_ue_security_capabilities_length]))
    pointer = pointer+1+replayed_ue_security_capabilities_length
    
    exit_while = False
    
    while len(ies)>pointer and exit_while == False:   
        if ies[pointer] == 0x55: #replayed nonce ue
            ies_list.append(("replayed nonce ue", ies[pointer+1:pointer+5]))
            pointer = pointer+5        
        elif ies[pointer] == 0x56: # nonce mme
            ies_list.append(("nonce mme", ies[pointer+1:pointer+5]))
            pointer = pointer+5     
        elif ies[pointer] // 16 == 0xc: # imeisv request C-
            ies_list.append(("imeisv request", ies[pointer]))
            pointer = pointer+1     
    
        elif ies[pointer] == 0x4f: # hash_mme
            hash_mme_length = ies[pointer + 1]
            hash_mme = ies[pointer+2:pointer+2+hash_mme_length]
            ies_list.append(("hash mme", hash_mme))
            pointer = pointer+2+hash_mme_length     
    
        elif ies[pointer] == 0x6f: # replayed_ue_additional_security_capability
            replayed_ue_additional_security_capability_length = ies[pointer + 1]
            replayed_ue_additional_security_capability = ies[pointer+2:pointer+2+replayed_ue_additional_security_capability_length]
            ies_list.append(("replayed ue additional security capability", replayed_ue_additional_security_capability))
            pointer = pointer+2+replayed_ue_additional_security_capability_length      
    
        ######## LAST ONE TO EXIT WHILE LOOP ###
        else: # didn't find more IEs
            exit_while = True    
    
    return ies_list

def nas_decode_emm_emm_status(ies):
    ies_list = []
    ies_list.append(("emm cause", ies[0]))

    return ies_list
    
def nas_decode_emm_emm_information(ies):
    ies_list = []
    
    pointer = 0
   
    exit_while = False
    
    while len(ies)>pointer and exit_while == False:   
        if ies[pointer] == 0x43: # full name for network
            full_name_for_network_length = ies[pointer + 1]
            full_name_for_network = ies[pointer+2:pointer+2+full_name_for_network_length]
            ies_list.append(("full name for network", full_name_for_network))
            pointer = pointer+2+full_name_for_network_length  
        elif ies[pointer] == 0x45: # short name for network
            short_name_for_network_length = ies[pointer + 1]
            short_name_for_network = ies[pointer+2:pointer+2+short_name_for_network_length]
            ies_list.append(("short name for network", short_name_for_network))
            pointer = pointer+2+short_name_for_network_length  
        elif ies[pointer] == 0x49: # network daylight saving time
            network_daylight_saving_time_length = ies[pointer + 1]
            network_daylight_saving_time = ies[pointer+2:pointer+2+network_daylight_saving_time_length]
            ies_list.append(("network daylight saving time", network_daylight_saving_time))
            pointer = pointer+2+network_daylight_saving_time_length  
            
        elif ies[pointer] == 0x46: # local time zone
            ies_list.append(("local time zone", ies[pointer+1:pointer+1]))
            pointer = pointer+2     
        elif ies[pointer] == 0x47: # universal time and local time zone
            ies_list.append(("universal time and local time zone", ies[pointer+1:pointer+8]))
            pointer = pointer+8      
    
        ######## LAST ONE TO EXIT WHILE LOOP ###
        else: # didn't find more IEs
            exit_while = True    
    
    return ies_list
    
def nas_decode_emm_downlink_nas_transport(ies):
    ies_list = []

    pointer = 0
    nas_message_container_length = ies[pointer]
    nas_message_container = ies[pointer+1:pointer+1+nas_message_container_length]

    ies_list.append(("nas message container",nas_message_container))
    
    return ies_list

        
def nas_decode_emm_downlink_generic_nas_transport(ies):
    ies_list = []
    ies_list.append(("generic message container type", ies[0]))

    pointer = 1
    generic_message_container_length = ies[pointer]*256+ies[pointer+1]
    generic_message_container = ies[pointer+2:pointer+2+generic_message_container_length]

    ies_list.append(("generic message container",generic_message_container))
    pointer = pointer+2+esm_message_container_length


    exit_while = False
    
    while len(ies)>pointer and exit_while == False:
        if ies[pointer] == 0x65: # additional information
            additional_information_length = ies[pointer + 1]
            additional_information = ies[pointer+2:pointer+2+additional_information_length]
            ies_list.append(("additional information", additional_information))
            pointer = pointer+2+additional_information_length    
    
        ######## LAST ONE TO EXIT WHILE LOOP ###
        else: # didn't find more IEs
            exit_while = True      
    
    return ies_list


def nas_decode_emm_cs_service_notification(ies):
    ies_list = []
    ies_list.append(("paging identity", ies[0]))
    
    pointer = 1
    
    exit_while = False
    
    while len(ies)>pointer and exit_while == False:   

        if ies[pointer] == 0x60: # CLI
            cli_length = ies[pointer + 1]
            cli = ies[pointer+2:pointer+2+cli_length]
            ies_list.append(("cli", cli))
            pointer = pointer+2+cli_length 
        elif ies[pointer] == 0x61: #ss code
            ies_list.append(("ss code", ies[pointer+1:pointer+1]))
            pointer = pointer+2
        elif ies[pointer] == 0x62: # lcs indicator
            ies_list.append(("lcs indicator", ies[pointer+1:pointer+1]))
            pointer = pointer+2
        elif ies[pointer] == 0x63: # lcs client identity
            lcs_client_identity_length = ies[pointer + 1]
            lcs_client_identity = ies[pointer+2:pointer+2+lcs_client_identity_length]
            ies_list.append(("lcs client identity", lcs_client_identity))
            pointer = pointer+2+lcs_client_identity_length  
    
        ######## LAST ONE TO EXIT WHILE LOOP ###
        else: # didn't find more IEs
            exit_while = True    
    
    return ies_list

        
        
#------------------------------------#
#                                    #
#   E S M  -  P r o c e d u r e s    #
#                                    #
#------------------------------------#        
         
#inputs: message_type and next bytes of nas with ies
def nas_decode_esm(message_type, ies):
    ies_list = []
    if message_type == 193: # activate default eps bearer context request
        ies_list = nas_decode_esm_activate_default_eps_bearer_context_request(ies)
    elif message_type == 197: # Activate dedicated EPS bearer context request
        ies_list = nas_decoded_esm_activate_dedicated_eps_bearer_context_request(ies)   
    elif message_type == 201: # Modify EPS bearer context request
        ies_list = nas_decode_esm_modify_eps_bearer_context_request(ies)        
    elif message_type == 205: # deactivate eps bearer context request
        ies_list = nas_decode_esm_deactivate_eps_bearer_context_request(ies)
    elif message_type == 209: # pdn connectivity reject
        ies_list = nas_decode_esm_pdn_connectivity_reject(ies)
    elif message_type == 211: # pdn disconnect reject
        ies_list = nas_decode_esm_pdn_disconnect_reject(ies)
    elif message_type == 217: # esm information request
        ies_list = nas_decode_esm_esm_information_request(ies)    
    elif message_type == 235: # esm data transport
        ies_list = nas_decode_esm_esm_data_transport(ies)    
    return ies_list
    
    
def nas_decode_esm_activate_default_eps_bearer_context_request(ies):
    ies_list = []
    eps_qos_length = ies[0]
    ies_list.append(("eps qos", ies[1:1+eps_qos_length]))
    pointer = 1 + eps_qos_length 
    access_point_name_length = ies[pointer]
    ies_list.append(("access point name", ies[pointer+1:pointer+1+access_point_name_length]))
    pointer += 1 + access_point_name_length 
    pdn_address_length = ies[pointer]
    ies_list.append(("pdn address", ies[pointer+1:pointer+1+pdn_address_length]))
    pointer += 1 + pdn_address_length   
    
    exit_while = False
    
    while len(ies)>pointer and exit_while == False:
        if ies[pointer] == 0x5D: #transaction identifier
            transaction_identifier_length = ies[pointer + 1]
            transaction_identifier = ies[pointer+2:pointer+2+transaction_identifier_length]
            ies_list.append(("transaction identifier", transaction_identifier))
            pointer = pointer+2+transaction_identifier_length 
        elif ies[pointer] == 0x30: #negotiated qos
            negotiated_qos_length = ies[pointer + 1]
            negotiated_qos = ies[pointer+2:pointer+2+negotiated_qos_length]
            ies_list.append(("negotiated qos", negotiated_qos))
            pointer = pointer+2+negotiated_qos_length 
        elif ies[pointer] == 0x34: #packet flow identifier
            packet_flow_identifier_length = ies[pointer + 1]
            packet_flow_identifier = ies[pointer+2:pointer+2+packet_flow_identifier_length]
            ies_list.append(("packet flow identifier", packet_flow_identifier))
            pointer = pointer+2+packet_flow_identifier_length     
        elif ies[pointer] == 0x5E: #apn-ambr
            apn_ambr_length = ies[pointer + 1]
            apn_ambr = ies[pointer+2:pointer+2+apn_ambr_length]
            ies_list.append(("apn-ambr", apn_ambr))
            pointer = pointer+2+apn_ambr_length   
        elif ies[pointer] == 0x27: #protocol configuration options
            protocol_configuration_options_length = ies[pointer + 1]
            protocol_configuration_options = ies[pointer+2:pointer+2+protocol_configuration_options_length]
            ies_list.append(("protocol configuration options", protocol_configuration_options))
            pointer = pointer+2+protocol_configuration_options_length  
        elif ies[pointer] == 0x32: #negotiated llc sapi
            ies_list.append(("negotiated llc sapi", ies[pointer+1:pointer+1]))
            pointer = pointer+2   
        elif ies[pointer] == 0x58: #esm cause
            ies_list.append(("esm cause", ies[pointer+1:pointer+1]))
            pointer = pointer+2 
        elif ies[pointer] // 16 == 0x8: # radio priority 8-
            ies_list.append(("radio priority", ies[pointer]))
            pointer = pointer+1           
        elif ies[pointer] // 16 == 0xB: # connectivity type B-
            ies_list.append(("connectivity type", ies[pointer]))
            pointer = pointer+1 
        elif ies[pointer] // 16 == 0xC: # wlan offload indication C-
            ies_list.append(("wlan offload indication", ies[pointer]))
            pointer = pointer+1             
        elif ies[pointer] // 16 == 0x9: # control plane only indication 9-
            ies_list.append(("control plane only indication", ies[pointer]))
            pointer = pointer+1     

        elif ies[pointer] == 0x7B: # extended_protocol_configuration_options
            extended_protocol_configuration_options_length = ies[pointer+1]*256+ies[pointer+2]
            extended_protocol_configuration_options = ies[pointer+3:pointer+3+extended_protocol_configuration_options_length]
            ies_list.append(("extended protocol configuration options",nas_decode(extended_protocol_configuration_options)))
            pointer = pointer+3+extended_protocol_configuration_options_length  
        elif ies[pointer] == 0x6E: #serving_plmn_rate_control
            serving_plmn_rate_control_length = ies[pointer + 1]
            serving_plmn_rate_control = ies[pointer+2:pointer+2+serving_plmn_rate_control_length]
            ies_list.append(("serving plmn rate control", serving_plmn_rate_control))
            pointer = pointer+2+serving_plmn_rate_control_length  

        elif ies[pointer] == 0x5F: #extended apn-ambr
            extended_apn_ambr_length = ies[pointer + 1]
            extended_apn_ambr = ies[pointer+2:pointer+2+extended_apn_ambr_length]
            ies_list.append(("extended apn-ambr", extended_apn_ambr))
            pointer = pointer+2+extended_apn_ambr_length  
            
        elif ies[pointer] == 0x5C: #extended_eps_qos
            extended_eps_qos_length = ies[pointer + 1]
            extended_eps_qos = ies[pointer+2:pointer+2+extended_eps_qos_length]
            ies_list.append(("extended eps qos", extended_eps_qos))
            pointer = pointer+2+extended_eps_qos_length              
            
            
        ######## LAST ONE TO EXIT WHILE LOOP ###
        else: # didn't find more IEs
            exit_while = True
            
    return ies_list            



    
def nas_decode_esm_modify_eps_bearer_context_request(ies):
    ies_list = []
    pointer = 0
    
    exit_while = False
    
    while len(ies)>pointer and exit_while == False:
        if ies[pointer] == 0x5B: #new eps qos
            new_eps_qos_length = ies[pointer + 1]
            new_eps_qos = ies[pointer+2:pointer+2+new_eps_qos_length]
            ies_list.append(("new eps qos", new_eps_qos))
            pointer = pointer+2+new_eps_qos_length 
        elif ies[pointer] == 0x36: #tft
            tft_length = ies[pointer + 1]
            tft = ies[pointer+2:pointer+2+tft_length]
            ies_list.append(("tft", tft))
            pointer = pointer+2+tft_length 
        elif ies[pointer] == 0x30: #new qos
            new_qos_length = ies[pointer + 1]
            new_qos = ies[pointer+2:pointer+2+new_qos_length]
            ies_list.append(("new qos", new_qos))
            pointer = pointer+2+new_qos_length 
        elif ies[pointer] == 0x32: #negotiated llc sapi
            ies_list.append(("negotiated llc sapi", ies[pointer+1:pointer+1]))
            pointer = pointer+2  
        elif ies[pointer] // 16 == 0x8: # radio priority 8-
            ies_list.append(("radio priority", ies[pointer]))
            pointer = pointer+1   
        elif ies[pointer] == 0x34: #packet flow identifier
            packet_flow_identifier_length = ies[pointer + 1]
            packet_flow_identifier = ies[pointer+2:pointer+2+packet_flow_identifier_length]
            ies_list.append(("packet flow identifier", packet_flow_identifier))
            pointer = pointer+2+packet_flow_identifier_length              
        elif ies[pointer] == 0x5E: #apn-ambr
            apn_ambr_length = ies[pointer + 1]
            apn_ambr = ies[pointer+2:pointer+2+apn_ambr_length]
            ies_list.append(("apn-ambr", apn_ambr))
            pointer = pointer+2+apn_ambr_length        
        elif ies[pointer] == 0x27: #protocol configuration options
            protocol_configuration_options_length = ies[pointer + 1]
            protocol_configuration_options = ies[pointer+2:pointer+2+protocol_configuration_options_length]
            ies_list.append(("protocol configuration options", protocol_configuration_options))
            pointer = pointer+2+protocol_configuration_options_length  
        elif ies[pointer] // 16 == 0xC: # wlan offload indication C-
            ies_list.append(("wlan offload indication", ies[pointer]))
            pointer = pointer+1   
        elif ies[pointer] == 0x33: #nbifom container
            nbifom_container_length = ies[pointer + 1]
            nbifom_container = ies[pointer+2:pointer+2+nbifom_container_length]
            ies_list.append(("nbifom container", nbifom_container))
            pointer = pointer+2+nbifom_container_length  
        elif ies[pointer] == 0x66: #header compression configuration
            header_compression_configuration_length = ies[pointer + 1]
            header_compression_configuration = ies[pointer+2:pointer+2+header_compression_configuration_length]
            ies_list.append(("header compression configuration", header_compression_configuration))
            pointer = pointer+2+header_compression_configuration_length  
        elif ies[pointer] == 0x7B: # extended_protocol_configuration_options
            extended_protocol_configuration_options_length = ies[pointer+1]*256+ies[pointer+2]
            extended_protocol_configuration_options = ies[pointer+3:pointer+3+extended_protocol_configuration_options_length]
            ies_list.append(("extended protocol configuration options",nas_decode(extended_protocol_configuration_options)))
            pointer = pointer+3+extended_protocol_configuration_options_length  
        elif ies[pointer] == 0x5F: #extended apn-ambr
            extended_apn_ambr_length = ies[pointer + 1]
            extended_apn_ambr = ies[pointer+2:pointer+2+extended_apn_ambr_length]
            ies_list.append(("extended apn-ambr", extended_apn_ambr))
            pointer = pointer+2+extended_apn_ambr_length             
        elif ies[pointer] == 0x5C: #extended_eps_qos
            extended_eps_qos_length = ies[pointer + 1]
            extended_eps_qos = ies[pointer+2:pointer+2+extended_eps_qos_length]
            ies_list.append(("extended eps qos", extended_eps_qos))
            pointer = pointer+2+extended_eps_qos_length              
            
            
        ######## LAST ONE TO EXIT WHILE LOOP ###
        else: # didn't find more IEs
            exit_while = True
            
    return ies_list  



def nas_decoded_esm_activate_dedicated_eps_bearer_context_request(ies):

    ies_list = []
    ies_list.append(("linked eps bearer identity", ies[0] % 16))

    eps_qos_length = ies[1]
    ies_list.append(("eps qos", ies[2:2+eps_qos_length]))
    pointer = 2 + eps_qos_length 

    tft_length = ies[pointer]
    ies_list.append(("tft", ies[pointer+1:pointer+1+tft_length]))
    pointer += 1 + tft_length 

    
    exit_while = False
    
    while len(ies)>pointer and exit_while == False:
        if ies[pointer] == 0x5D: #transaction identifier
            transaction_identifier_length = ies[pointer + 1]
            transaction_identifier = ies[pointer+2:pointer+2+transaction_identifier_length]
            ies_list.append(("transaction identifier", transaction_identifier))
            pointer = pointer+2+transaction_identifier_length 
        elif ies[pointer] == 0x30: #negotiated qos
            negotiated_qos_length = ies[pointer + 1]
            negotiated_qos = ies[pointer+2:pointer+2+negotiated_qos_length]
            ies_list.append(("negotiated qos", negotiated_qos))
            pointer = pointer+2+negotiated_qos_length 
        elif ies[pointer] == 0x34: #packet flow identifier
            packet_flow_identifier_length = ies[pointer + 1]
            packet_flow_identifier = ies[pointer+2:pointer+2+packet_flow_identifier_length]
            ies_list.append(("packet flow identifier", packet_flow_identifier))
            pointer = pointer+2+packet_flow_identifier_length     
        elif ies[pointer] == 0x33: #nbifom container
            nbifom_container_length = ies[pointer + 1]
            nbifom_container = ies[pointer+2:pointer+2+nbifom_container_length]
            ies_list.append(("nbifom container", nbifom_container))
            pointer = pointer+2+nbifom_container_length   
        elif ies[pointer] == 0x27: #protocol configuration options
            protocol_configuration_options_length = ies[pointer + 1]
            protocol_configuration_options = ies[pointer+2:pointer+2+protocol_configuration_options_length]
            ies_list.append(("protocol configuration options", protocol_configuration_options))
            pointer = pointer+2+protocol_configuration_options_length  
        elif ies[pointer] == 0x32: #negotiated llc sapi
            ies_list.append(("negotiated llc sapi", ies[pointer+1:pointer+1]))
            pointer = pointer+2   
        elif ies[pointer] == 0x58: #esm cause
            ies_list.append(("esm cause", ies[pointer+1:pointer+1]))
            pointer = pointer+2 
        elif ies[pointer] // 16 == 0x8: # radio priority 8-
            ies_list.append(("radio priority", ies[pointer]))
            pointer = pointer+1           
        elif ies[pointer] // 16 == 0xC: # wlan offload indication C-
            ies_list.append(("wlan offload indication", ies[pointer]))
            pointer = pointer+1             
   

        elif ies[pointer] == 0x7B: # extended_protocol_configuration_options
            extended_protocol_configuration_options_length = ies[pointer+1]*256+ies[pointer+2]
            extended_protocol_configuration_options = ies[pointer+3:pointer+3+extended_protocol_configuration_options_length]
            ies_list.append(("extended protocol configuration options",nas_decode(extended_protocol_configuration_options)))
            pointer = pointer+3+extended_protocol_configuration_options_length  
 
            
        elif ies[pointer] == 0x5C: #extended_eps_qos
            extended_eps_qos_length = ies[pointer + 1]
            extended_eps_qos = ies[pointer+2:pointer+2+extended_eps_qos_length]
            ies_list.append(("extended eps qos", extended_eps_qos))
            pointer = pointer+2+extended_eps_qos_length              
            
            
        ######## LAST ONE TO EXIT WHILE LOOP ###
        else: # didn't find more IEs
            exit_while = True
            
    return ies_list  
def nas_decode_esm_deactivate_eps_bearer_context_request(ies):
    ies_list = []
    ies_list.append(("esm cause", ies[0]))  
    pointer = 1
    exit_while = False
    
    while len(ies)>pointer and exit_while == False:    
        if ies[pointer] == 0x27: #protocol configuration options
            protocol_configuration_options_length = ies[pointer + 1]
            protocol_configuration_options = ies[pointer+2:pointer+2+protocol_configuration_options_length]
            ies_list.append(("protocol configuration options", protocol_configuration_options))
            pointer = pointer+2+protocol_configuration_options_length  


        ######## LAST ONE TO EXIT WHILE LOOP ###
        else: # didn't find more IEs
            exit_while = True

    return ies_list   

def nas_decode_esm_pdn_connectivity_reject(ies):
    ies_list = []
    ies_list.append(("esm cause", ies[0]))  
    pointer = 1
    exit_while = False
    
    while len(ies)>pointer and exit_while == False:    
        if ies[pointer] == 0x27: #protocol configuration options
            protocol_configuration_options_length = ies[pointer + 1]
            protocol_configuration_options = ies[pointer+2:pointer+2+protocol_configuration_options_length]
            ies_list.append(("protocol configuration options", protocol_configuration_options))
            pointer = pointer+2+protocol_configuration_options_length  

        elif ies[pointer] == 0x37: #t3396 value
            t3396_value_length = ies[pointer + 1]
            t3396_value = ies[pointer+2:pointer+2+t3396_value_length]
            ies_list.append(("t3396 value", t3396_value))
            pointer = pointer+2+t3396_value_length  


        ######## LAST ONE TO EXIT WHILE LOOP ###
        else: # didn't find more IEs
            exit_while = True

    return ies_list 

def nas_decode_esm_pdn_disconnect_reject(ies):
    ies_list = []
    ies_list.append(("esm cause", ies[0]))  
    pointer = 1
    exit_while = False
    
    while len(ies)>pointer and exit_while == False:    
        if ies[pointer] == 0x27: #protocol configuration options
            protocol_configuration_options_length = ies[pointer + 1]
            protocol_configuration_options = ies[pointer+2:pointer+2+protocol_configuration_options_length]
            ies_list.append(("protocol configuration options", protocol_configuration_options))
            pointer = pointer+2+protocol_configuration_options_length  


        ######## LAST ONE TO EXIT WHILE LOOP ###
        else: # didn't find more IEs
            exit_while = True

    return ies_list 
def nas_decode_esm_esm_information_request(ies):
    pass  #done no IEI      
    
    
def nas_decode_esm_esm_data_transport(ies):
    ies_list = []
    pointer = 0
    user_data_container_length = ies[pointer]*256+ies[pointer+1]
    user_data_container = ies[pointer+2:pointer+2+user_data_container_length]
    ies_list.append(("user data container",user_data_container))
    pointer = pointer+2+user_data_container_length
    
    exit_while = False
    
    while len(ies)>pointer and exit_while == False:
        if ies[pointer] // 16 == 0xF: # release assistance indication F-
            ies_list.append(("release assistance indication", ies[pointer]))
            pointer = pointer+1 
        
        ######## LAST ONE TO EXIT WHILE LOOP ###
        else: # didn't find more IEs
            exit_while = True
    
    return ies_list    
    
######################################################################################################################
######################################################################################################################
######################################################################################################################

#[(protocol_discriminator, security_header), (iei1, format, value), (iei2, format, value), etc...]
#  iei = 0 if mandatory. i[2] in bytes format
#  other values as 0x19. i[2] in bytes format
#  if half byte it should be like 0xF. the other part i[2] is in decimal
#
#input nas_list with sequencial   
def nas_encode(nas_list):    
    nas = b''
    protocol_discriminator = nas_list[0][0]
    security_header = nas_list[0][1]
    nas += bytes([(security_header<<4)+protocol_discriminator])
    for i in range(1,len(nas_list)):
        if nas_list[i][0] == 0:
            if nas_list[i][1] == 'V':
                nas += nas_list[i][2]
            elif nas_list[i][1] == 'LV':
                nas += bytes([len(nas_list[i][2])]) + nas_list[i][2]
            elif nas_list[i][1] == 'LV-E':
                nas += bytes([len(nas_list[i][2])//256]) + bytes([len(nas_list[i][2])%256]) + nas_list[i][2]
        else:
            if nas_list[i][1] == "TV":
                if nas_list[i][0] < 16: #one hex symbol is just one byte len. always TV
                    nas += bytes([(nas_list[i][0]<<4) + nas_list[i][2]])
                else:
                    nas += bytes([nas_list[i][0]]) + nas_list[i][2]
            if nas_list[i][1] == "TLV":
                nas += bytes([nas_list[i][0]]) + bytes([len(nas_list[i][2])]) + nas_list[i][2]    
            if nas_list[i][1] == "TLV-E":
                nas += bytes([nas_list[i][0]]) + bytes([len(nas_list[i][2])//256]) + bytes([len(nas_list[i][2])%256]) + nas_list[i][2]     
    
    
    return nas
    
    
 


######################################################################################################################
######################################################################################################################
######################################################################################################################
#
#  specific Fucntions to decode/encode some NAS IEI
#
#


def decode_eps_mobile_identity(iei):
    iei_list = []
    type_of_identity = iei[0] % 8
    iei_list.append(('type of identity', type_of_identity))
    if type_of_identity == 1 or type_of_identity == 3: #imsi or imei
        odd_even_indicator = (iei[0]%16)>>3
        digits = str(iei[0]//16)
        for i in range(1,len(iei)):
            digits += str(iei[i]%16) + str(iei[i]//16)
        if odd_even_indicator == 0:
            digits = digits[:-1]
        digits = int(digits)
        iei_list.append(('digits', digits))        
    elif type_of_identity == 6:
        iei_list.append(('mcc',int(str(iei[1]%16) + str(iei[1]//16) + str(iei[2]%16))))
        if iei[2] // 16 == 15: #1111
            iei_list.append(('mnc',int(str(iei[3]%16) + str(iei[3]//16))))
        else:
            iei_list.append(('mnc',int(str(iei[3]%16) + str(iei[3]//16) + str(iei[2]//16))))
        iei_list.append(('mme group id', 256*iei[4] + iei[5]))
        iei_list.append(('mme code', iei[6]))    
        iei_list.append(('m-tmsi', struct.unpack("!I", iei[7:11])[0]))    
        iei_list.append(('s-tmsi', iei[6:11]))
    return iei_list
    

def decode_pdn_address(iei):
    iei_list = []
    pdn_type_value = iei[0] % 8
    iei_list.append(('pdn type value', pdn_type_value))
    if pdn_type_value == 1: # ipv4
        iei_list.append(('ipv4',socket.inet_ntop(socket.AF_INET, iei[1:1+4])))
    elif pdn_type_value == 2: # ipv6
        iei_list.append(('ipv6', socket.inet_ntop(socket.AF_INET6, iei[1:1+8] + 8*b'\x00')))
    elif pdn_type_value == 3: # ipv4v6
        iei_list.append(('ipv6', socket.inet_ntop(socket.AF_INET6, iei[1:1+8] + 8*b'\x00')))
        iei_list.append(('ipv4',socket.inet_ntop(socket.AF_INET, iei[9:9+4])))
    return iei_list

def decode_apn(byteArray):
    a = []
    pos = 0
    while pos < len(byteArray):
        i = int(byteArray[pos])
        for x in range(pos+1, pos+1+i):
            a.append(chr(byteArray[x]))

        a.append(".")
        pos = pos+1+i

    return [('apn', ''.join(a)[:-1])]

def encode_apn(apn):
    apn_bytes = bytes()
    apn_l = apn.split(".") 
    for word in apn_l:
        apn_bytes += struct.pack("!B", len(word)) + word.encode()
    return apn_bytes
    
def encode_guti(mcc_mnc, mme_group_id, mme_code, m_tmsi):
    guti = b'\xf6'
    mcc_mnc = str(mcc_mnc)
    
    if len(mcc_mnc) == 5: mcc_mnc += 'f'
    guti += unhexlify(mcc_mnc[1] + mcc_mnc[0] + mcc_mnc[5] +mcc_mnc[2]+ mcc_mnc[4]+ mcc_mnc[3])
    guti += struct.pack("!H", mme_group_id)
    guti += struct.pack("!B", mme_code)
    guti += struct.pack("!L", m_tmsi)
    return guti

def encode_imsi(imsi):
    imsi = str(imsi)
    aux = unhexlify(imsi[0] + '9')
    for i in range(1,15,2):
        aux += unhexlify(imsi[i+1] + imsi[i])
    return aux

def encode_imei(imei):
    imei = str(imei)
    if len(imei) % 2 == 0:
        imei += 'f'
        aux = unhexlify(imei[0] + '3')
    else:
        aux = unhexlify(imei[0] + 'b')    
    for i in range(1,len(imei)-1,2):
        aux += unhexlify(imei[i+1] + imei[i])
    return aux 
    