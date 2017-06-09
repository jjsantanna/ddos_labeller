#!/usr/bin/env python
import cgi
import cgitb; cgitb.enable()
import os, sys

debug=True
threshold=100

print "Content-Type: text/html\n"

print """
<!DOCTYPE html>
<html lang="en">
<head>
	<title>Multi-Vector DDoS Attack Classifier</title>
	<meta charset="utf-8" />
	<meta name="viewport" content="width=device-width" />
	<meta name="author" content="Jair Santanna. @jalterebro" />
	<meta name="description" content="Practical Classifier of Multi-vector DDoS Attack." />
"""


# HTML_TEMPLATE = """<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
# <html><head><title>DDoS Classifier</title>
# <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
# </head><body><h1>running...</h1>
# </body>
# </html>"""

# print HTML_TEMPLATE


# Destination of the input raw file
upload_dir = "../testedfiles"

form = cgi.FieldStorage()
    
if form.has_key("inputfile") and form["inputfile"].file:
	print "Copying the file...<br><br>"
	
	fileitem = form["inputfile"]

	copiedfile = file (os.path.join(upload_dir, fileitem.filename), 'wb')
	while 1:
		chunk = fileitem.file.read(100000)
		if not chunk: break
		copiedfile.write (chunk)
	copiedfile.close()
	print "File copyed!<br><br>"

	###
	# Starting the classification process

	input_file = os.path.join(upload_dir, fileitem.filename)
	raw_input_size=os.stat(input_file).st_size
	if debug: print("File size: "+str(raw_input_size)+" Bytes")
	
	import time
	time0 = time.time()

	import argparse
	import dpkt
	import socket
	import os

	if debug: print("Input: "+input_file)
	if debug: print("Threshold[%]: "+str(threshold))

	if debug: print("Converting file...")

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

	        print >> outputfile,\
	        str(ip_ttl)+';'+\
	        str(ip_proto)+';'+\
	        str(ip_length)+';'+\
	        str(ip_src)+';'+\
	        str(ip_dst)+';'+\
	        str(sport)+';'+\
	        str(dport)+';'+\
	        str(tcp_flag)+';'+\
	        str(fragments)+';'+\
	        str(http_request_method)
	        #         str(timestamp)+';'+\

	####
	#Saving the conversion time
	conversion_time = time.time() - time0

	if debug: print("Output: "+output_file)

  