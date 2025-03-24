#!/usr/bin/python3 


# Example code using scapy Python library 
# counts packets, TCP packets, UDP packets, and shows the time-of-arrival of HTTP requests 
# (c) 2023 R. P. Martin, GPL version 2

from scapy.all import *
import sys
import time
import math



pcap_filename = sys.argv[1]
ip_server = sys.argv[2]
port_server = int(sys.argv[3])


def dl( p, q ):
    i = 0
    dkl = 0.0
    while i < 10:
        # print(i)
        if( p[i] != 0 ):
            # print("in ")
            temp = p[i] * math.log2    (    ( p[i] / q[i])     )
            
            
           
            dkl += temp
            i+=1
        else:
            i+=1
            continue
        
        
        
    
    
    return dkl



class node:
    total = 0  # Class variable

    def __init__(self, source, dest, port, mark, timestamp):
        self.source = source
        self.dest = dest
        self.port = port
        self.mark = mark  #this will store value 1 or 2, 1 for request, 2 for respond
        self.timestamp = timestamp
        
        node.total += 1

    def display(self):
        print(self.source + " " + self.dest)
        print(self.port)
        print(self.mark)
        print(self.timestamp)
        print(node.total)
        # print("============================")
    # def update_year(self, new_year):
        # self.year = new_year










# make sure to load the HTTP layer or your code wil silently fail
load_layer("http")

# name of the pcap file to load 
# pcap_filename = "pcap1.pcap"

# example counters 
number_of_packets_total = 0  
number_of_tcp_packets = 0
number_of_udp_packets = 0

allresponse = []
allrequest = []

processed_file = rdpcap(pcap_filename)  # read in the pcap file 
sessions = processed_file.sessions()    #  get the list of sessions 


countPacketPairp = 0
countPacketPairpp = 0


for session in sessions:  
    
                     
    for packet in sessions[session]:    # for each packet in each session
        
        
        number_of_packets_total = number_of_packets_total + 1  #increment total packet count 
        if packet.haslayer(TCP):        # check is the packet is a TCP packet
            
            
    
            number_of_tcp_packets = number_of_tcp_packets + 1   # count TCP packets 
            source_ip = packet[IP].src   # note that a packet is represented as a python hash table with keys corresponding to 
            dest_ip = packet[IP].dst     # layer field names and the values of the hash table as the packet field values
            
            # print(source_ip)
            # print(dest_ip)
            # print(packet[TCP].)
            
            
            if (packet.haslayer(HTTP)):
                countPacketPairpp+=1
                if HTTPRequest in packet: 
                    # print ("the request have a dport at ")
                    # print(packet[TCP].dport )
                    # print(type(packet[TCP].dport))
                    if dest_ip == ip_server and packet[TCP].dport == port_server:

                        # print(HTTPRequest) 
                        # print("==============================") 
                        arrival_time = packet.time
                        # print ("Got a TCP packet part of an HTTP request at time: %0.4f for server IP %s" % (arrival_time,dest_ip))
                        # packet.show()

                        port = packet[TCP].sport


                        # print(source_ip)
                        # print(dest_ip)
                        # print(type(source_ip))
                        # print(type(arrival_time))
                        # print(arrival_time - 10.1111)

                        temp = node(source_ip, dest_ip, port, 1, arrival_time )

                        allrequest.append(temp)

                        countPacketPairp+=1

                elif HTTPResponse in packet:
                    # print ("the packet have a sport at")
                    # print(packet[TCP].sport )
                    if source_ip == ip_server and packet[TCP].sport == port_server:
                        # print("==============================")
                        # print(source_ip)
                        # print(dest_ip)
                        # packet.show()
                        port = packet[TCP].dport
                        arrival_time1 = packet.time
                    
#   
                        # print(type(source_ip))
                        # print(type(arrival_time))
                        # print(arrival_time - 10.1111)
#   
                        temp1 = node(source_ip, dest_ip, port, 2, arrival_time1 )
                        allresponse.append(temp1)


                        countPacketPairp+=1
                else:
                    #packet.show()
                    pass
                    
                    
        else:
            if packet.haslayer(UDP):
                number_of_udp_packets = number_of_udp_packets + 1
                
# print("Got %d packets total, %d TCP packets and %d UDP packets" % (number_of_packets_total, number_of_tcp_packets,number_of_udp_packets))

countPacketPair = 0



timediff = []
for r in allrequest:
    # r.display()
    for t in allresponse:
        if(r.source == t.dest and r.dest == t.source and r.port == t.port and r.mark != t.mark):
            # r.display()
            # t.display()
            countPacketPair+=1
            
            diff = t.timestamp - r.timestamp
            # print(diff)
            # print(type(diff))
            # print("===========-------===========")
            
            timediff.append(diff)
            
timediff.sort()
average = 0.0
totle = 0.0
for t in timediff:
 
    totle += t
 
average1 = totle / countPacketPair
average = round(average1, 5)
 
 

a = round(countPacketPair * 0.25)
b = round(countPacketPair * 0.50)
c = round(countPacketPair * 0.75)
d = round(countPacketPair * 0.95)
e = round(countPacketPair * 0.99)


aa = round(timediff[a], 5)
bb = round(timediff[b], 5)
cc = round(timediff[c], 5)
dd = round(timediff[d], 5)
ee = round(timediff[e-1], 5)




b1uckets = []
b2uckets = []

timebetween = (timediff[countPacketPair - 1] - 0) / 10





upperbound = 0 + timebetween

# math.exp(10) # e^10
iii = 0 # the iii's packet
i = 0 
b1uckets.append(0)


bo1undarry = [] # lowerbound
bo2undarry = [] # upperbound
bo1undarry.append(0)


while i < countPacketPair:
    if timediff[i] <= upperbound:
        # print(iii)
        b1uckets[iii] += 1
        i+=1
        
    elif( timediff[i] > upperbound):
        # we add a new bucket
        # new lowerbound of a bucket 
        bo2undarry.append(i - 1)
        bo1undarry.append(i)
        
        upperbound = upperbound + timebetween
        iii += 1
        b1uckets.append(0)
        
        # print (iii)
    else:
        print("wrong")
        break
    
bo2undarry.append(countPacketPair-1)  



# print(bo1undarry)
# print(bo2undarry)
i = 0
while i < 10:
    b1uckets[i] = b1uckets[i] / countPacketPair
    i+=1


lamuda = 1.0 / float(average)   

# print(bo2undarry)




timebetween = (timediff[countPacketPair - 1] - 0) / 10

i = 0
while (i < 9):
    
    # if bo2undarry[i] >= bo1undarry[i]:
    #     fx = 1 - (math.exp(-lamuda * timediff[bo1undarry[i]]  ) )
    #     fx = 1 - (math.exp(-lamuda * timediff[0]))
    #     gx = 1 - (math.exp(-lamuda * timediff[bo2undarry[i]]  ) )

    #     print(gx)
        
    # elif(bo2undarry[i] < bo1undarry[i]):
    #     fx = 0
    #     gx = 0
    
    fx = 1.0 - math.exp( (-lamuda) * ( i * timebetween))
    gx = 1.0 - math.exp((-lamuda) * ( (i+1) * timebetween))

    # print(gx - fx)

    # if (fx > gx):
    #     b2uckets.append(fx - gx)
    # elif(gx > fx):
    #     b2uckets.append(gx - fx)
        
    # elif(gx == fx): 
    #     b2uckets.append(0)
    b2uckets.append(gx - fx)
    i +=1 


# print(b1uckets)
# print(b2uckets)
fx = 1.0 - math.exp(-(lamuda) * ( 9 * timebetween))
gx = 1.0 - math.exp((-lamuda )*  ( float('inf')))
b2uckets.append(gx - fx)


# print(gx - fx)
# print(b2uckets)
# print(b1uckets)
dkl = dl(b1uckets, b2uckets)





print("AVERAGE LATENCY: %.5f" % average)
print("PERCENTILES: %0.5f %0.5f %.5f %.5f %.5f" % (aa, bb, cc, dd, ee ))
print("KL DIVERGENCE: %0.5f" % dkl)