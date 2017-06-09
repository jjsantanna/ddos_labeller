#!/usr/bin/env python
import cgi
import cgitb; cgitb.enable()
import os, sys

threshold=100

print "Content-Type: text/html\n"

upload_dir = "../testedfiles"

form = cgi.FieldStorage()
    
if not form.has_key("inputfile") and not form["inputfile"].file:
    sys.exit()
    

fileitem = form["inputfile"]

######
#Copying the original file
copiedfile = file (os.path.join(upload_dir, fileitem.filename), 'wb')
while 1:
    chunk = fileitem.file.read(100000)
    if not chunk: break
    copiedfile.write (chunk)
copiedfile.close()

#####
# Starting the classification process
input_file = os.path.join(upload_dir, fileitem.filename)

enrichment_folder = '../enrichments/'


# ### For python script (instead of ipython) 

# In[1]:

# import sys

# if __name__ == '__main__':
#     if len(sys.argv) < 2:
#         print 'usage: python %s <input_file>' % (sys.argv[0])
#         sys.exit(2)

#     input_file = sys.argv[1]
#     debug=False
# enrichment_folder = 'enrichments/'


# ### For Jupyter Notebook (instead of python script) 

# In[2]:

# input_file='../TITAN/TITAN-ESSYN-S-01_2014-12-22_22_33_09.pcap'
# threshold=100
# debug=False

# import warnings
# warnings.filterwarnings('ignore')
# enrichment_folder = 'enrichments/'


# <h2 align='center'>==========================================================<br>
# Debug or not Debug?!</h2>

# In[ ]:

debug=False


# <h2 align='center'>==========================================================<br>
# Needed libraries for data analysis</h2>

# In[3]:

import pandas as pd #more info at http://pandas.pydata.org/
import numpy as np #more info at http://www.numpy.org/


# <h2 align='center'>==========================================================<br>
# Getting the size of the input (raw) file (in bytes)</h2>

# In[4]:

#Saving the file size in bytes!
import os
raw_input_size=os.stat(input_file).st_size

if debug: print("File size: "+str(raw_input_size)+" Bytes")


# <h2 align='center'>==========================================================<br>
# Converting the input file (using dpkt and python 2.7)</h2>

# In[5]:

import time
time0 = time.time()

import argparse
import dpkt
import socket
import os

if debug: print("Input: "+input_file)
if debug: print("Threshold[%]: "+str(threshold))

####
#Preparing output file (considering the input file a complet path or a symbolic path)
if input_file.startswith("../"):
    output_file=".."+input_file.split('.')[2]+".txt" 
else:
    output_file=input_file.split('.')[0]+".txt"

outputfile = open(output_file,'w')

inputfile = open(input_file)
pcapfile = dpkt.pcap.Reader(inputfile)

for ts, buf in pcapfile:
    eth = dpkt.ethernet.Ethernet(buf)

    #FILTERING ONLY FOR IPv4 instead of packets ARP or IPv6
    if eth.type == dpkt.ethernet.ETH_TYPE_IP:
        ip = eth.data #Loading the content of the ethernet into a variable 'ip'
        
        timestamp = ts #1
        ip_ttl = ip.ttl #2
        
        ip_proto = ip.p #3
        sport = ""
        dport= ""
        tcp_flag =""
        http_request_method=""
        if (ip_proto != 6) and (ip_proto != 17): #It is not TCP or UDP
            continue
            
        ip_length = ip.len #4
        ip_src = socket.inet_ntoa(ip.src) #5
        ip_dst = socket.inet_ntoa(ip.dst) #6
        
        try: proto = ip.data #Loading the content of the 'ip' into a variable 'protocol' that can be for example ICMP, TCP, and UDP.
        except:
            continue
        
        sport = proto.sport #7
        dport = proto.dport #8


        if ip.p == 6 :
            try:
                tcp_flag += ("F" if (int( proto.flags & dpkt.tcp.TH_FIN ) != 0) else ".") #27
                tcp_flag += ("S" if (int( proto.flags & dpkt.tcp.TH_SYN ) != 0) else ".") #26
                tcp_flag += ("R" if (int( proto.flags & dpkt.tcp.TH_RST ) != 0) else ".") #25
                tcp_flag += ("P" if (int( proto.flags & dpkt.tcp.TH_PUSH) != 0) else ".") #24
                tcp_flag += ("A" if (int( proto.flags & dpkt.tcp.TH_ACK ) != 0) else ".") #23
                tcp_flag += ("U" if (int( proto.flags & dpkt.tcp.TH_URG ) != 0) else ".") #22
                tcp_flag += ("E" if (int( proto.flags & dpkt.tcp.TH_ECE ) != 0) else ".") #21
                tcp_flag += ("C" if (int( proto.flags & dpkt.tcp.TH_CWR ) != 0) else ".") #20
            except:
                print "EXCEPTION TCP FLAG"  if debug else next

            if (proto.dport == 80) or (proto.dport == 443):
                    if proto.data == '':
                        http_request_method=''
                    else:
                        try:
                            http_request_method = dpkt.http.Request(proto.data).method
                        except:
                            http_request_method = ''

            
        fragments = 1 if (int(ip.off & dpkt.ip.IP_MF)!= 0) else 0  #8 This flag is set to a 1 for all fragments except the last one            

        print >> outputfile,        str(ip_ttl)+';'+        str(ip_proto)+';'+        str(ip_length)+';'+        str(ip_src)+';'+        str(ip_dst)+';'+        str(sport)+';'+        str(dport)+';'+        str(tcp_flag)+';'+        str(fragments)+';'+        str(http_request_method)
        #         str(timestamp)+';'+\

####
#Saving the conversion time
conversion_time = time.time() - time0

if debug: print("Output: "+output_file)


# <h2 align='center'>==========================================================<br>
# Loading the converted input trace into</h2>

# In[6]:

time0 = time.time()

####
#Defining the same order as in the converted data (Note that I removed the timestamp because in the current
#version this information is not added)
columns=[
#     'timestamp',\
         'ip_ttl',\
         'ip_proto',\
         'ip_length',\
         'ip_src',\
         'ip_dst',\
         'sport',\
         'dport',\
         'tcp_flag',\
         'fragments',\
         'http_data']

####
#Loading the converted data into a csv
df = pd.read_csv(output_file,delimiter=";", names=columns,low_memory=False)

total_packets=len(df)
####
#Saving the loading time
loading_time=time.time() - time0


# <h2 align='center'>==========================================================<br>
# Functions to enrich the analysis (e.g., convert a protocol or port number in name) </h2>

# In[3]:

df_port_name = pd.read_csv(enrichment_folder+'port_name.txt',delimiter=",", names=['port_num','port_name'])
df_ip_proto_name = pd.read_csv(enrichment_folder+'ip_proto_name.txt',delimiter=",", names=['proto_num','proto_name'])
    
def get_ip_proto_name(ip_proto_number):
    try:
        return df_ip_proto_name[df_ip_proto_name['proto_num']==ip_proto_number]['proto_name'].values[0]
    except:
        return str(ip_proto_number)
    
def get_port_name(port_number):
    try:
        return df_port_name[df_port_name['port_num']==port_number]['port_name'].values[0]+" service port"
    except:
        return "port "+str(int(port_number))
    
def get_tcp_flag_name(tcp_flags_str):
    tcp_flags=""
    try:
        tcp_flags += ("FIN" if (tcp_flags_str.find('F') != -1) else next) 
    except:
        next
    try:
        tcp_flags += ("SYN" if (tcp_flags_str.find('S')!= -1) else next) 
    except:
        next
        
    try:
        tcp_flags += ("RST" if tcp_flags_str.find('R') != -1 else next)
    except:
        next
        
    try:
        tcp_flags += ("PUSH" if tcp_flags_str.find('P') != -1 else next) 
    except:
        next
        
    try:
        tcp_flags += ("ACK" if tcp_flags_str.find('A') != -1 else next)
    except:
        next
        
    try:
        tcp_flags += ("URG" if tcp_flags_str.find('U') != -1 else next) 
    except:
        next
        
    try:
        tcp_flags += ("ECE" if tcp_flags_str.find('E') != -1 else next)
    except:
        next
        
    try:
        tcp_flags += ("CWR" if tcp_flags_str.find('C') != -1 else next)
    except:
        next
   
        
    return tcp_flags      


# <h2 align='center'>====================================================================<br>
# Determining the target and the IP protocol used in the attack</h2>

# In[7]:

time0 = time.time()

top_ip_dst = df['ip_dst'].value_counts().index[0]
if debug: print("Top dst IP: "+ top_ip_dst)

top_ip_proto = df[df['ip_dst']==top_ip_dst]['ip_proto'].value_counts().index[0]
if debug: print("Top IP protocol: "+str(top_ip_proto)) 

####
#Performing a first filter based on the top_ip_dst (target IP), the source IPs canNOT be from the \16 of the
#target IP, and the top IP protocol that targeted the top_ip_dst
df_filtered=df[(df['ip_dst']==top_ip_dst) &              ~df['ip_src'].str.contains(".".join(top_ip_dst.split('.')[0:2]),na=False) &              (df['ip_proto'] == top_ip_proto)]

####
#Calculating the number of packets after the first filter
total_packets_filtered = len(df_filtered)
if debug: print("Number of packets: "+str(total_packets_filtered))


# <h2 align='center'>====================================================================<br>
# Defining the attack trace to be classified and <br>calculate some statistics to be use in the classification</h2>

# In[8]:

attack_case="-1"
ttl_variation_threshold=4
no_attack_found=False
time0 = time.time()

#####
# ASSUMPTION: DDoS attack is a high concentration of packets with same characteristics (pattern)

traffic_patterns=[]
i=0

while (len(df_filtered)>0):
    ####
    # For attacks in the IP protocol level
    attack_label = get_ip_proto_name(top_ip_proto)+"-based attack"    
    
    ####
    # For attacks based on TCP or UDP, which have source and destination ports
    if ((top_ip_proto == 6) or (top_ip_proto == 17)):     
        
        if debug: print("\n####################\nANALYSIS:\n####################")
        ####
        #Calculating the distribution of source ports based on the first filter
        percent_src_ports = df_filtered['sport'].value_counts().divide(float(total_packets_filtered)/100)
        if debug: print("\nSource ports frequency")
        if debug: print(percent_src_ports.head())

        ####
        #Calculating the distribution of destination ports after the first filter
        percent_dst_ports = df_filtered['dport'].value_counts().divide(float(total_packets_filtered)/100)
        if debug: print("\nDestination ports frequency") 
        if debug: print(percent_dst_ports.head()) 

        #####
        # Using the top 1 (source or destination) port to analyse a pattern of packets
        if (len(percent_src_ports) >0) and (len(percent_dst_ports)>0) :
            if percent_src_ports.values[0] > percent_dst_ports.values[0]:
                df_pattern = df_filtered[df_filtered['sport']==percent_src_ports.keys()[0]]
            else:
                df_pattern = df_filtered[df_filtered['dport']==percent_dst_ports.keys()[0]] 
        else:
            break
            
        if debug: print("\n####################\nPATTERN "+str(i)+"\n####################")

        #####    
        #Calculating the total number of packets involved in the attack
        pattern_packets = len(df_pattern)

        #####    
        #Calculating the percentage of the current pattern compared to the raw input file
        representativeness = float(pattern_packets)*100/float(total_packets_filtered)
        attack_label = input_file+'; In %.2f' % representativeness+"% of packets targeting "+top_ip_dst+"; "+ attack_label

        #####
        # Checking the existence of HTTP data
        http_data = df_pattern['http_data'].value_counts().divide(float(pattern_packets)/100)

        #####
        # Checking the existence of TCP flags
        percent_tcp_flags = df_pattern['tcp_flag'].value_counts().divide(float(pattern_packets)/100)

        #####
        # Calculating the number of source IPs involved in the attack
        ips_involved= len(df_pattern['ip_src'].unique())
        attack_label = attack_label +"; involving "+str(ips_involved)+ " IP(s)"

        ####
        #Calculating the distribution of TTL variation (variation -> number of IPs)
        ttl_variations = df_pattern.groupby(['ip_src'])['ip_ttl'].agg(np.ptp).value_counts().sort_index()

        ####
        #Calculating the distribution of IP fragments (fragmented -> percentage of packets)
        percent_fragments = df_pattern['fragments'].value_counts().divide(float(pattern_packets)/100)    

        ####
        #Calculating the distribution of source ports that remains
        percent_src_ports = df_pattern['sport'].value_counts().divide(float(pattern_packets)/100)
        if debug: print("\nSource ports frequency") 
        if debug: print(percent_src_ports.head()) 

        ####
        #Calculating the distribution of destination ports after the first filter
        percent_dst_ports = df_pattern['dport'].value_counts().divide(float(pattern_packets)/100)
        if debug: print("\nDestination ports frequency")
        if debug: print(percent_dst_ports.head()) 
            
        ####                                                              
        # There are 3 possibilities of attacks cases!                                                                     
        if (percent_src_ports.values[0]==100):
            if (len(percent_dst_ports)==1):
                if debug: print("\nCASE 1: 1 source port to 1 destination port") if debug else next
                attack_label = attack_label+"; using "+get_port_name(percent_src_ports.keys()[0])+                                                "; to target "+get_port_name(percent_dst_ports.keys()[0])+"["+'%.1f' % percent_dst_ports.values[0]+"%]" 
            else:
                if debug: print("\nCASE 2: 1 source port to a set of destination ports") if debug else next    
                if (percent_dst_ports.values[0] >= 50 ):
                    attack_label = attack_label+"; using "+get_port_name(percent_src_ports.keys()[0])+                                            "; to target a set of ("+str(len(percent_dst_ports))+") ports, such as "+get_port_name(percent_dst_ports.keys()[0])+"["+'%.2f' % percent_dst_ports.values[0]+"%]"+" and "+get_port_name(percent_dst_ports.keys()[1])+"["+'%.2f' % percent_dst_ports.values[1]+"%]"
                elif (percent_dst_ports.values[0] >= 33 ):
                    attack_label = attack_label+"; using "+get_port_name(percent_src_ports.keys()[0])+                                                    "; to target a set of ("+str(len(percent_dst_ports))+") ports, such as "+get_port_name(percent_dst_ports.keys()[0])+"["+'%.2f' % percent_dst_ports.values[0]+"%]"+"; "+get_port_name(percent_dst_ports.keys()[1])+"["+'%.2f' % percent_dst_ports.values[1]+"%], and "+get_port_name(percent_dst_ports.keys()[2])+"["+'%.2f' % percent_dst_ports.values[2]+"%]"
                else:
                    attack_label = attack_label+"; using "+get_port_name(percent_src_ports.keys()[0])+                                                    "; to target a set of ("+str(len(percent_dst_ports))+") ports, such as "+get_port_name(percent_dst_ports.keys()[0])+"["+'%.2f' % percent_dst_ports.values[0]+"%]"+"; "+get_port_name(percent_dst_ports.keys()[1])+"["+'%.2f' % percent_dst_ports.values[1]+"%], and "+get_port_name(percent_dst_ports.keys()[2])+"["+'%.2f' % percent_dst_ports.values[2]+"%]"    
        else:
            if (len(percent_src_ports)==1):
                if debug: print("\nCASE 1: 1 source port to 1 destination port") if debug else next
                attack_label = attack_label+"; using "+get_port_name(percent_src_ports.keys()[0])+"["+'%.1f' % percent_src_ports.values[0]+"%]"+                                                "; to target "+get_port_name(percent_dst_ports.keys()[0])+"["+'%.1f' % percent_dst_ports.values[0]+"%]" 

            else:
                if debug: print("\nCASE 3: 1 source port to a set of destination ports") if debug else next
                if (percent_src_ports.values[0] >= 50 ):
                    attack_label = attack_label+"; using a set of ("+str(len(percent_src_ports))+") ports, such as "+get_port_name(percent_src_ports.keys()[0])+"["+'%.2f' % percent_src_ports.values[0]+"%] and "+get_port_name(percent_src_ports.keys()[1])+"["+'%.2f' % percent_src_ports.values[1]+"%]"+                                                "; to target "+get_port_name(percent_dst_ports.keys()[0])+"["+'%.1f' % percent_dst_ports.values[0]+"%]"
                elif (percent_src_ports.values[0] >= 33 ):
                    attack_label = attack_label+"; using a set of ("+str(len(percent_src_ports))+") ports, such as "+get_port_name(percent_src_ports.keys()[0])+"["+'%.2f' % percent_src_ports.values[0]+"%], "+get_port_name(percent_src_ports.keys()[1])+"["+'%.2f' % percent_src_ports.values[1]+"%], and "+get_port_name(percent_src_ports.keys()[2])+"["+'%.2f' % percent_src_ports.values[2]+"%]"+                                                "; to target "+get_port_name(percent_dst_ports.keys()[0])+"["+'%.1f' % percent_dst_ports.values[0]+"%]"
                else:
                    attack_label = attack_label+"; using a set of ("+str(len(percent_src_ports))+") ports, such as "+get_port_name(percent_src_ports.keys()[0])+"["+'%.2f' % percent_src_ports.values[0]+"%], "+get_port_name(percent_src_ports.keys()[1])+"["+'%.2f' % percent_src_ports.values[1]+"%], "+get_port_name(percent_src_ports.keys()[2])+"["+'%.2f' % percent_src_ports.values[2]+"%]"+"; and "+get_port_name(percent_src_ports.keys()[3])+"["+'%.2f' % percent_src_ports.values[3]+"%]"+                                                "; to target "+get_port_name(percent_dst_ports.keys()[0])+"["+'%.1f' % percent_dst_ports.values[0]+"%]"

        ####
        # Testing HTTP request 
        if len(http_data)>0 and ((percent_dst_ports.index[0]==80) or (percent_dst_ports.index[0]==443)):
            attack_label = attack_label+"; "+http_data.index[0]

        ####
        # Testing TCP flags
        if (len(percent_tcp_flags) > 0) and (percent_tcp_flags.values[0]>50):
            attack_label =  attack_label+"; TCP flags: "+get_tcp_flag_name(percent_tcp_flags.index[0])+"["+'%.1f' % percent_tcp_flags.values[0]+"%]"

        ####
        # IP fragmentation    
        if (percent_fragments.values[0] > 0) and (percent_fragments.index[0]==1):
            attack_label = attack_label + "; involving IP fragmentation"

        ####
        # IP spoofing (if (more than 0) src IPs had the variation of the ttl higher than a treshold)
        if (ttl_variations[::-1].values[0] > 0) and (ttl_variations[::-1].index[0] >= ttl_variation_threshold):
            attack_label= attack_label+"; (likely involving) spoofed IPs"
        else:
        ####
        # Reflection and Amplification    
            if percent_src_ports.values[0]>=1:
                attack_label= attack_label+"; Reflection & Amplification"

        
        if debug: print(attack_label)
        traffic_patterns.insert( i, attack_label)
        
        merged=df_filtered.merge(df_pattern, indicator=True, how='outer')
        df_filtered=merged[merged['_merge'] == 'left_only']
        df_filtered.drop('_merge', axis=1, inplace=True)
        
        i=i+1


# In[9]:

print '\n'.join(map(str, traffic_patterns))


# In[10]:

####
#Just a message
# os.system('say "Done!"')


# In[11]:

# print(  input_file,\
#         threshold,
#         attack_case,\
#         raw_input_size,\
#         conversion_time,\
#         loading_time,\
#         pre_analysis_time,\
#         filtering_attack_time,\
#         attack_classification_time,\
#         attack_label) if debug else next

