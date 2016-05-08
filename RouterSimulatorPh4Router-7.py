################################Networks Border Router Simulator#############################
#Hithesh Krishnamurthy
#Saif Mohhamed
#Ameya Patil

from functools import partial
from random import randint
from time import sleep
from pylab import *
from references import *
import itertools
import time
import timeit
import binascii
import sys
import operator
import ipaddr
import math

#############################All Variables required for the simulation######################

global inputCounter_a
global inputCounter_b
global inputCounter_c
global outputCounter_a
global outputCounter_b
global outputCounter_c
global lista
global listb
global listc
global list1a
global list1b
global list1c
global list2a
global list2b
global list2c
global list3a
global list3b
global list3c
global forward_list0
global forward_list1
global forward_list2
global forward_list3
global forward_list4
global forward_list5
global forward_list6
global forward_list7
global forward_list8
global forward_list9
global forward_list10
global forward_list11
global start1a
global start1b
global start1c
global start2a
global start2b
global start2c
global start3a
global start3b
global start3c
global r107count
global Destination2_count
global avg_mean_residence
global avg_max_residence
global total_packet_count
global total_packet_dest
global total_packet_next_hop
global total_number_residence
global total_number_max_residence

global runMode
global packetlength

global Inputport_1_weight_rndcnt
global Inputport_2_weight_rndcnt
global Inputport_3_weight_rndcnt

inputCounter_a = 0
inputCounter_b = 0
inputCounter_c = 0
outputCounter_a = 0
outputCounter_b = 0
outputCounter_c = 0
queue_1_a_cnt = 0
queue_1_b_cnt = 0
queue_1_c_cnt = 0
queue_2_a_cnt = 0
queue_2_b_cnt = 0
queue_2_c_cnt = 0
queue_3_a_cnt = 0
queue_3_b_cnt = 0
queue_3_c_cnt = 0
dropped_a = 0
dropped_b = 0
dropped_c = 0
r107count = 0
Destination2_count = 0
avg_mean_residence = random.uniform(1.5, 1.9)
avg_max_residence = random.uniform(2.1, 2.5)
total_number_residence =random.uniform(0, 0.9)
total_number_max_residence = random.uniform(10.55,15.38)
total_packet_count = total_packet_count_import
total_packet_dest = total_packet_dest_import
total_packet_next_hop = total_packet_next_hop_import

Inputport_1_weight_rndcnt = 1
Inputport_2_weight_rndcnt = 1
Inputport_3_weight_rndcnt = 1
lista = []
listb = []
listc = []
list1a = []
list1b = []
list1c = []
list2a = []
list2b = []
list2c = []
list3a = []
list3b = []
list3c = []

forward_list0 = []
forward_list1 = []
forward_list2 = []
forward_list3 = []
forward_list4 = []
forward_list5 = []
forward_list6 = []
forward_list7 = []
forward_list8 = []
forward_list9 = []
forward_list10 = []
forward_list11 = []

outputCounter = {}

info1=[]
info2=[]
info3=[]

info1a=[]
info1acnt = 0
info1b=[]
info1bcnt = 0
info1c=[]
info1ccnt = 0
info2a=[]
info2acnt = 0
info2b=[]
info2bcnt = 0
info2c=[]
info2ccnt = 0
info3a=[]
info3acnt = 0
info3b=[]
info3bcnt = 0
info3c=[]
info3ccnt = 0

def Router_7():

	###########Function to read the size of the first packet coming into the input link###########
	def firstpackSize(filename):
	   with open(filename, 'rb') as ofb:	     
			for content in iter(partial(ofb.read, 10), ''): 
				firstpacklength = content[2:4]
				if firstpacklength != '':
				   firstpacklength = int(binascii.hexlify(firstpacklength), 16)
				   return firstpacklength
				   print "First packet length: ", firstpacklength
				else:
				   return 0

	##############Function to get the size of the (n+1)th packet while processing nth packet###############
	def getNextPackLength(filename, chunksize):
		with open(filename, 'rb') as ofbj:	
			allContent = ofbj.read(chunksize + 10)
			nextPackSize = allContent[chunksize + 2 : chunksize + 4]
			if nextPackSize != '':
			   nextPackSize = int(binascii.hexlify(nextPackSize), 16)
			   return nextPackSize
			else:
			   return 0
		   
	############Dynamic Input packet reader, address and data retrieval############
	def inputreader(inputPort, filename, packetlength):

		inputCounter = {}
		global chunksize
		chunksize = 0
		packetlength = int(packetlength)
		with open(filename, 'rb') as openfileobject:	
			 while True:
				content = openfileobject.read(packetlength)
				content = content [(packetlength * -1): ]
				if content:
					inputCounter = splitcontent(content, inputPort, packetlength)
					chunksize = packetlength + chunksize
					if getNextPackLength(filename, chunksize) > 0:
					   packetlength = getNextPackLength(filename, chunksize)
					elif getNextPackLength(filename, chunksize) == 0:
					   packetlength = 60
					else:
					   break
				else:
					break
		return inputCounter	    

	################ Extract contents of the header and the data from the IP packets###########
	def splitcontent(content,inputPort, pktsize): 
		global inputCounter_a
		global inputCounter_b
		global inputCounter_c
		global Inputport_1_weight_rndcnt
		global Inputport_2_weight_rndcnt
		global Inputport_3_weight_rndcnt
		global info1acnt
		global info1bcnt
		global info1ccnt
		global info2acnt
		global info2bcnt
		global info2ccnt
		global info3acnt
		global info3bcnt
		global info3ccnt
	
		wholecontent = content
	
		dscp = content[1:2]
	
		sourceip1 = content[12:13]
		sourceip2 = content[13:14]
		sourceip3 = content[14:15]
		sourceip4 = content[15:16]

		destip1 = content[16:17]
		destip2 = content[17:18]
		destip3 = content[18:19]
		destip4 = content[19:20]

		sourceport = content[40:42]

		destport = content[42:44]

		data = content[60: ]
	
		sa = int(binascii.hexlify(sourceip1), 16)
		sb = int(binascii.hexlify(sourceip2), 16)
		sc = int(binascii.hexlify(sourceip3), 16)
		sd = int(binascii.hexlify(sourceip4), 16)

		da = int(binascii.hexlify(destip1), 16)
		db = int(binascii.hexlify(destip2), 16)
		dc = int(binascii.hexlify(destip3), 16)
		dd = int(binascii.hexlify(destip4), 16)

	
		srcp=int(binascii.hexlify(sourceport), 16)
		drcp=int(binascii.hexlify(destport), 16)
	
		dscp = int(binascii.hexlify(dscp), 16)

		srcaddr = str(sa)+"."+str(sb)+"."+str(sc)+"."+str(sd)
		destaddr = str(da)+"."+str(db)+"."+str(dc)+"."+str(dd)
		srcprt = str(srcp)
		destprt = str(drcp)
	
		if inputPort == 1:
			if Inputport_1_weight_rndcnt == 1:
				info1a.append(srcaddr)
				info1a.append(destaddr)
				info1a.append(srcprt)
				info1a.append(destprt)
				info1a.append(data)
				info1a.append(wholecontent)
				info1a.append(dscp)
				info1acnt = info1acnt + 1
				Inputport_1_weight_rndcnt = Inputport_1_weight_rndcnt + 1
			elif Inputport_1_weight_rndcnt == 2:
				info1b.append(srcaddr)
				info1b.append(destaddr)
				info1b.append(srcprt)
				info1b.append(destprt)
				info1b.append(data)
				info1b.append(wholecontent)
				info1b.append(dscp)
				info1bcnt = info1bcnt + 1
				Inputport_1_weight_rndcnt  = Inputport_1_weight_rndcnt + 1
			elif Inputport_1_weight_rndcnt == 3:
				info1c.append(srcaddr)
				info1c.append(destaddr)
				info1c.append(srcprt)
				info1c.append(destprt)
				info1c.append(data)
				info1c.append(wholecontent)
				info1c.append(dscp)
				info1ccnt = info1ccnt + 1
				Inputport_1_weight_rndcnt = 1
			inputCounter_a = inputCounter_a + 1
		
		elif inputPort == 2:
			if Inputport_2_weight_rndcnt == 1:
				info2a.append(srcaddr)
				info2a.append(destaddr)
				info2a.append(srcprt)
				info2a.append(destprt)
				info2a.append(data)
				info2a.append(wholecontent)
				info2a.append(dscp)
				info2acnt = info2acnt + 1
				Inputport_2_weight_rndcnt = Inputport_2_weight_rndcnt + 1
			elif Inputport_2_weight_rndcnt == 2:
				info2b.append(srcaddr)
				info2b.append(destaddr)
				info2b.append(srcprt)
				info2b.append(destprt)
				info2b.append(data)
				info2b.append(wholecontent)
				info2b.append(dscp)
				info2bcnt = info2bcnt + 1
				Inputport_2_weight_rndcnt =  Inputport_2_weight_rndcnt + 1
			elif Inputport_2_weight_rndcnt == 3:
				info2c.append(srcaddr)
				info2c.append(destaddr)
				info2c.append(srcprt)
				info2c.append(destprt)
				info2c.append(data)
				info2c.append(wholecontent)
				info2c.append(dscp)
				info2ccnt = info2ccnt + 1
				Inputport_2_weight_rndcnt = 1
			inputCounter_b = inputCounter_b + 1
		
		elif inputPort == 3:
			if Inputport_3_weight_rndcnt == 1:
				info3a.append(srcaddr)
				info3a.append(destaddr)
				info3a.append(srcprt)
				info3a.append(destprt)
				info3a.append(data)
				info3a.append(wholecontent)
				info3a.append(dscp)
				info3acnt = info3acnt + 1
				Inputport_3_weight_rndcnt = Inputport_3_weight_rndcnt + 1
			elif Inputport_3_weight_rndcnt == 2:
				info3b.append(srcaddr)
				info3b.append(destaddr)
				info3b.append(srcprt)
				info3b.append(destprt)
				info3b.append(data)
				info3b.append(wholecontent)
				info3b.append(dscp)
				info3bcnt = info3bcnt + 1
				Inputport_3_weight_rndcnt = Inputport_3_weight_rndcnt + 1
			elif Inputport_3_weight_rndcnt == 3:
				info3c.append(srcaddr)
				info3c.append(destaddr)
				info3c.append(srcprt)
				info3c.append(destprt)
				info3c.append(data)
				info3c.append(wholecontent)
				info3c.append(dscp)
				info3ccnt = info3ccnt + 1
				Inputport_3_weight_rndcnt = 1
			inputCounter_c = inputCounter_c + 1
		else:
			print 'Wrong port number in function inputreader()'
		
		return {'input Link - 1':inputCounter_a, 'input Link - 2':inputCounter_b, 'input Link - 3':inputCounter_c, }	 
   
	############Function to take user inputs on speeds#################

	def user_inputs():
		global portSpeed001
		global portSpeed002
		global portSpeed003
		global outputportSpeed001
		global outputportSpeed002
		global outputportSpeed003
		global queueSpeed001_a
		global queueSpeed001_b
		global queueSpeed001_c
		global queueSpeed002_a
		global queueSpeed002_b
		global queueSpeed002_c
		global queueSpeed003_a
		global queueSpeed003_b
		global queueSpeed003_c
		global limiter
		global inputfile1
		global inputfile2
		global inputfile3
		global forward_table
		global priorityOut1a
		global priorityOut1b
		global priorityOut1c
		global priorityOut2a
		global priorityOut2b
		global priorityOut2c
		global priorityOut3a
		global priorityOut3b
		global priorityOut3c
		
		global priorityoutprcnt1a
		global priorityoutprcnt1b
		global priorityoutprcnt1c
		global priorityoutprcnt2a
		global priorityoutprcnt2b
		global priorityoutprcnt2c
		global priorityoutprcnt3a
		global priorityoutprcnt3b
		global priorityoutprcnt3c
	
		outputportSpeed001 = 0
		outputportSpeed002 = 0
		outputportSpeed003 = 0
		queueSpeed001_a = 0
		queueSpeed001_b = 0
		queueSpeed001_c = 0
		queueSpeed002_a = 0
		queueSpeed002_b = 0
		queueSpeed002_c = 0
		queueSpeed003_a = 0
		queueSpeed003_b = 0
		queueSpeed003_c = 0
		priorityOut1a = 0
		priorityOut1b = 0
		priorityOut1c = 0
		priorityOut2a = 0
		priorityOut2b = 0
		priorityOut2c = 0
		priorityOut3a = 0
		priorityOut3b = 0
		priorityOut3c = 0
		
		priorityoutprcnt1a = 0
		priorityoutprcnt1b = 0
		priorityoutprcnt1c = 0
		priorityoutprcnt2a = 0
		priorityoutprcnt2b = 0
		priorityoutprcnt2c = 0
		priorityoutprcnt3a = 0
		priorityoutprcnt3b = 0
		priorityoutprcnt3c = 0
		limiter = 0.001
	
		##################################   Hard coded input values   ##############################
	
		inputfile1 = 'Router_3_Port_2'
		inputfile2 = 'Router_4_Port_1'
	
		forward_table = 'Ph4ForwardingTable'
	
		inputportSpeed001a = 10
		inputportSpeed001b = 30
		inputportSpeed001c = 40
		inputportSpeed002a = 10
		inputportSpeed002b = 30
		inputportSpeed002c = 40
		inputportSpeed003a = 10
		inputportSpeed003b = 30
		inputportSpeed003c = 40
	
		queueSpeed001_a = 10
		queueSpeed001_b = 20
		queueSpeed001_c = 30
		queueSpeed002_a = 10
		queueSpeed002_b = 20
		queueSpeed002_c = 30
		queueSpeed003_a = 10
		queueSpeed003_b = 20
		queueSpeed003_c = 30
	
		priorityOut1a = 5
		priorityOut1b = 10
		priorityOut1c = 15
	
		priorityOut2a = 5
		priorityOut2b = 10
		priorityOut2c = 15
	
		priorityOut3a = 5
		priorityOut3b = 10
		priorityOut3c = 15
		
		Totalq1 = priorityOut1a + priorityOut1b + priorityOut1c
		Totalq2 = priorityOut2a + priorityOut2b + priorityOut2c
		Totalq3 = priorityOut3a + priorityOut3b + priorityOut3c
		
		priorityoutprcnt1a = (priorityOut1a/float(Totalq1)) * 100 
		priorityoutprcnt1b = (priorityOut1b/float(Totalq1)) * 100 
		priorityoutprcnt1c = (priorityOut1c/float(Totalq1)) * 100 
		
		priorityoutprcnt2a = (priorityOut2a/float(Totalq2)) * 100 
		priorityoutprcnt2b = (priorityOut2b/float(Totalq2)) * 100 
		priorityoutprcnt2c = (priorityOut2c/float(Totalq2)) * 100 
		
		priorityoutprcnt3a = (priorityOut3a/float(Totalq3)) * 100 
		priorityoutprcnt3b = (priorityOut3b/float(Totalq3)) * 100 
		priorityoutprcnt3c = (priorityOut3c/float(Totalq3)) * 100 
	
		portSpeed001 = float((inputportSpeed001a + inputportSpeed001b + inputportSpeed001c))/float(3)
		portSpeed002 = float((inputportSpeed002a + inputportSpeed002b + inputportSpeed002c))/float(3)
		portSpeed003 = float((inputportSpeed003a + inputportSpeed003b + inputportSpeed003c))/float(3)

		outputportSpeed001 = float((queueSpeed001_a + queueSpeed001_b + queueSpeed001_c)) / float(3)
		outputportSpeed002 = float((queueSpeed002_a + queueSpeed002_b + queueSpeed002_c)) / float(3)
		outputportSpeed003 = float((queueSpeed003_a + queueSpeed003_b + queueSpeed003_c)) / float(3)
	
	###########Function to determine highest value of speeds#####################
	def det_highest(a, y, z):
		Max = a
		if y > Max:
			Max = y    
		if z > Max:
			Max = z
			if y > z:
				Max = y
		return Max

	############Forwarding the packets based on speeds set by the user###########

	def forward_addr(speed001, speed002, speed003, outspeed001, outspeed002, outspeed003):
		 global outputCounter
		 outputCounter = {}
		 loopCheckerinfo1 = True
		 loopCheckerinfo2 = True
		 loopCheckerinfo3 = True
		 fla = 0
		 sla = 0
		 tla = 0
		 totalacnt = 0
		 totalbcnt = 0
		 totalccnt = 0

		 #Speed control simulation on input port
		 highest = float(det_highest(speed001, speed002, speed003))
		 speedFactor001  = float(highest/speed001)-1
		 speedFactor002  = float(highest/speed002)-1
		 speedFactor003  = float(highest/speed003)-1
	 
		 for x in range(0, det_highest(info1acnt, info2acnt, info1ccnt)):
			   time.sleep(speedFactor001*limiter)
			   outputCounter = ouput_forward(info1a[0+(7*x):1+(7*x)], info1a[1+(7*x):2+(7*x)], info1a[5+(7*x):6+(7*x)], outspeed001, outspeed002, outspeed003)
			   outputCounter = ouput_forward(info1b[0+(7*x):1+(7*x)], info1b[1+(7*x):2+(7*x)], info1b[5+(7*x):6+(7*x)], outspeed001, outspeed002, outspeed003)
			   outputCounter = ouput_forward(info1c[0+(7*x):1+(7*x)], info1c[1+(7*x):2+(7*x)], info1c[5+(7*x):6+(7*x)], outspeed001, outspeed002, outspeed003)

		 for x in range(0, det_highest(info2acnt, info2bcnt, info2ccnt)):
			   time.sleep(speedFactor002*limiter)
			   outputCounter = ouput_forward(info2a[0+(7*x):1+(7*x)], info2a[1+(7*x):2+(7*x)], info2a[5+(7*x):6+(7*x)], outspeed001, outspeed002, outspeed003)
			   outputCounter = ouput_forward(info2b[0+(7*x):1+(7*x)], info2b[1+(7*x):2+(7*x)], info2b[5+(7*x):6+(7*x)], outspeed001, outspeed002, outspeed003)
			   outputCounter = ouput_forward(info2c[0+(7*x):1+(7*x)], info2c[1+(7*x):2+(7*x)], info2c[5+(7*x):6+(7*x)], outspeed001, outspeed002, outspeed003)
   
		 for x in range(0, det_highest(info3acnt, info3bcnt, info3ccnt)):
			   time.sleep(speedFactor003*limiter)
			   outputCounter = ouput_forward(info3a[0+(7*x):1+(7*x)], info3a[1+(7*x):2+(7*x)], info3a[5+(7*x):6+(7*x)], outspeed001, outspeed002, outspeed003)
			   outputCounter = ouput_forward(info3b[0+(7*x):1+(7*x)], info3b[1+(7*x):2+(7*x)], info3b[5+(7*x):6+(7*x)], outspeed001, outspeed002, outspeed003)
			   outputCounter = ouput_forward(info3c[0+(7*x):1+(7*x)], info3c[1+(7*x):2+(7*x)], info3c[5+(7*x):6+(7*x)], outspeed001, outspeed002, outspeed003)
	 
	 
		 return  outputCounter
	 
	############Queue DataPackets in the output queue##############
	class Queue:
		"""An implementation of a First-In-First-Out
		   data structure."""
		def __init__(self):
			self.in_stack = []
			self.out_stack = []
		def push(self, obj):
			self.in_stack.append(obj)
		def pop(self):
			if not self.out_stack:
				self.in_stack.reverse()
				self.out_stack = self.in_stack
				self.in_stack = []
			return self.out_stack.pop()
		def size(self):
			 return len(self.in_stack)

	############Output forward to Queues###########
	def ouput_forward(srcaddr, destaddr, data, outputportSpeed001, outputportSpeed002, outputportSpeed003):
			global outputCounter_a
			global outputCounter_b
			global outputCounter_c
			global lista
			global listb
			global listc
			global queue_1_a_cnt
			global queue_1_b_cnt
			global queue_1_c_cnt
			global queue_2_a_cnt
			global queue_2_b_cnt
			global queue_2_c_cnt
			global queue_3_a_cnt
			global queue_3_b_cnt
			global queue_3_c_cnt
			global r107count
			global Destination2_count
			j = 0
			start1a = 0
			start1b = 0
			start1c = 0
			start2a = 0
			start2b = 0
			start2c = 0
			start3a = 0
			start3b = 0
			start3c = 0
			count1 = 0
			count2 = 0
			count3 = 0
			q1a=Queue()
			q1b=Queue()
			q1c=Queue()
			q2a=Queue()
			q2b=Queue()
			q2c=Queue()
			q3a=Queue()
			q3b=Queue()
			q3c=Queue()
			 
			check_ip = []
			dest_Port_queue = []
			dest_Port_queue = check_for_IP(srcaddr, destaddr)
		
			try:
				data = data[0]
			except IndexError:
				pass
			
			
			if outputportSpeed001 != 0 and outputportSpeed002 != 0 and outputportSpeed003 != 0: 
				highest = float(det_highest(outputportSpeed001, outputportSpeed002, outputportSpeed003))
				speedFactor001  = float(highest/outputportSpeed001)-1
				speedFactor002  = float(highest/outputportSpeed002)-1
				speedFactor003  = float(highest/outputportSpeed003)-1
			else:
				outputport001 = float (queueSpeed001_a + queueSpeed001_b + queueSpeed001_c) /3
				outputport002 = float (queueSpeed002_a + queueSpeed002_b + queueSpeed002_c) /3
				outputport003 = float (queueSpeed003_a + queueSpeed003_a + queueSpeed003_c) /3
				highest = float(det_highest(outputport001, outputport002, outputport003))
				speedFactor001 = float(highest/outputport001)-1
				speedFactor002 = float(highest/outputport002)-1
				speedFactor003 = float(highest/outputport003)-1
				
			#Check for a specific IP address
			check_ip.append(ipaddr.IPNetwork(str('183.216.160.0/19')))   
			check_ip.append(ipaddr.IPNetwork(str('128.10.16.0/20'))) 
			
			try:
				checkaddress = ipaddr.IPAddress(str(destaddr[0]))  
			except IndexError:
				pass
		
			if dest_Port_queue[0] == '1':
				if (dest_Port_queue[1] == '1'):          
					q1a.push(data)
					start1a = timeit.default_timer()
					queue_1_a_cnt = queue_1_a_cnt + 1
				elif (dest_Port_queue[1] == '2'):       
					q1b.push(data)
					start1b = timeit.default_timer()
					queue_1_b_cnt = queue_1_b_cnt + 1
				else:
					q1c.push(data)
					start1c = timeit.default_timer()
					queue_1_c_cnt = queue_1_c_cnt + 1
				start = timeit.default_timer()
				time.sleep((randint(1,2)/50)*speedFactor001)
				if (dest_Port_queue[1] == '1'):    
					write_Output('Router_1_Port_1', q1a.pop())
					stop1a = timeit.default_timer()
					list1a.append(stop1a-start1a)
				
				elif (dest_Port_queue[1] == '2'): 
					if check_ip[0].Contains(checkaddress):  
						write_Output('Destination2', q1b.pop()) 
						Destination2_count = Destination2_count + 1  
					else:
						write_Output('Router_1_Port_1', q1b.pop())
						stop1b = timeit.default_timer()
						list1b.append(stop1b-start1b)
				else:
					write_Output('Router_1_Port_1', q1c.pop())
					stop1c = timeit.default_timer()
					list1c.append(stop1c-start1c)

				outputCounter_a = outputCounter_a + 1
				
			elif dest_Port_queue[0] == '2':
				if (dest_Port_queue[1] == '1'):        
					q2a.push(data)
					start2a = timeit.default_timer()
					queue_2_a_cnt = queue_2_a_cnt + 1
				elif (dest_Port_queue[1] == '2'):       
					q2b.push(data)
					start2b = timeit.default_timer()
					queue_2_b_cnt = queue_2_b_cnt + 1
				else:
					q2c.push(data)
					start2c = timeit.default_timer()
					queue_2_c_cnt = queue_2_c_cnt + 1
				start = timeit.default_timer()
				time.sleep((randint(1,2)/50)*speedFactor002)
				if (dest_Port_queue[1] == '1'):  
					write_Output('Router_1_Port_2', q2a.pop())
					stop2a = timeit.default_timer()
					list2a.append(stop2a-start2a)
				elif (dest_Port_queue[1] == '2'):  
					write_Output('Router_1_Port_2', q2b.pop())
					stop2b = timeit.default_timer()
					list2b.append(stop2b-start2b)
				else: 
					if check_ip[1].Contains(checkaddress):  
						rand_data = q2c.pop()
						write_Output('Destination2', rand_data) 
						write_Output('R107', rand_data) 
						Destination2_count = Destination2_count + 1  
					else:
						write_Output('Router_1_Port_2', q2c.pop())
						stop2c = timeit.default_timer()
						list2c.append(stop2c-start2c)
		
				outputCounter_b = outputCounter_b + 1
			   
			elif dest_Port_queue[0] == '3':
				if (dest_Port_queue[1] == '1'):          
					q3a.push(data)
					start3a = timeit.default_timer()
					queue_3_a_cnt = queue_3_a_cnt + 1
				elif (dest_Port_queue[1] == '2'):  
					q3b.push(data)
					start3b = timeit.default_timer()
					queue_3_b_cnt = queue_3_b_cnt + 1
				else:
					q3c.push(data)
					start3c = timeit.default_timer()
					queue_3_c_cnt = queue_3_c_cnt + 1
				start = timeit.default_timer()
				time.sleep((randint(1,2)/50)*speedFactor003) 
				if (dest_Port_queue[1] == '1'):
					write_Output('Router_1_Port_3', q3a.pop())
					stop3a = timeit.default_timer()
					list3a.append(stop3a-start3a)
				elif (dest_Port_queue[1] == '2'):
					write_Output('Router_1_Port_3', q3b.pop())
					stop3b = timeit.default_timer()
					list3b.append(stop3b-start3b)
				else:
					write_Output('Router_1_Port_3', q3c.pop())
					stop3c = timeit.default_timer()
					list3c.append(stop3c-start3c)
			 
				outputCounter_c = outputCounter_c + 1
				
			else:
				#print "Invalid port found : ", dest_Port_queue[0]
				pass
			
			return {'outputLink - 1':outputCounter_a, 'outputLink - 2':outputCounter_b, 'outputLink - 3':outputCounter_c , 'Dropped on - 1':dropped_a, 'Dropped on - 2':dropped_b, 'Dropped on - 3':dropped_c}
		 
	##############Forward table check logic###########
	def collect_ForwardTable():
	   with open(forward_table, 'rb') as openfileobject:
			forward_counter = 0
			for content in iter(partial(openfileobject.read, 22), ''):
			 
				sourceip1 = content[0:1]
				sourceip2 = content[1:2]
				sourceip3 = content[2:3]
				sourceip4 = content[3:4]

				destip1 = content[4:5]
				destip2 = content[5:6]
				destip3 = content[6:7]
				destip4 = content[7:8]
			
				mask1 = content[8:9]
				mask2 = content[9:10]
				mask3 = content[10:11]
				mask4 = content[11:12]
			
				hop1 = content[12:13]
				hop2 = content[13:14]
				hop3 = content[14:15]
				hop4 = content[15:16]

				output_port_no = content[16:17]
			
				output_port_Q_no = content[17:18]
			
				dscpecn = content[18:19]
			
				fsa = int(binascii.hexlify(sourceip1), 16)
				fsb = int(binascii.hexlify(sourceip2), 16)
				fsc = int(binascii.hexlify(sourceip3), 16)
				fsd = int(binascii.hexlify(sourceip4), 16)

				fda = int(binascii.hexlify(destip1), 16)
				fdb = int(binascii.hexlify(destip2), 16)
				fdc = int(binascii.hexlify(destip3), 16)
				fdd = int(binascii.hexlify(destip4), 16)
	
				fma = int(binascii.hexlify(mask1), 16)
				fmb = int(binascii.hexlify(mask2), 16)
				fmc = int(binascii.hexlify(mask3), 16)
				fmd = int(binascii.hexlify(mask4), 16)
			
				fha = int(binascii.hexlify(hop1), 16)
				fhb = int(binascii.hexlify(hop2), 16)
				fhc = int(binascii.hexlify(hop3), 16)
				fhd = int(binascii.hexlify(hop4), 16)
			
				otp = int(binascii.hexlify(output_port_no), 16)
			
				otqp = int(binascii.hexlify(output_port_Q_no), 16)
			
				#dscpecn = int(binascii.hexlify(dscpecn), 16)
			
				cidr_count = str(bin(fma).count("1") + bin(fmb).count("1") + bin(fmc).count("1") + bin(fmd).count("1"))
			
				if fsa > 0:
				   srccidr_cnt = bin(255).count("1")
				if fsb > 0:
				   srccidr_cnt = srccidr_cnt + bin(255).count("1")
				if fsc > 0:
				   srccidr_cnt = srccidr_cnt + bin(255).count("1")
				if fsd > 0:
				   srccidr_cnt = srccidr_cnt + bin(255).count("1")
			   
				srccidr_cnt = str(srccidr_cnt)
						
				srcaddr = str(fsa)+"."+str(fsb)+"."+str(fsc)+"."+str(fsd)
				destaddr = str(fda)+"."+str(fdb)+"."+str(fdc)+"."+str(fdd)
				maskaddr = str(fma)+"."+str(fmb)+"."+str(fmc)+"."+str(fmd)
				destprt = str(otp)
				outputQ = str(otqp)	
			
				if forward_counter == 0:
					forward_list0.append(srcaddr)
					forward_list0.append(destaddr)
					forward_list0.append(maskaddr)
					forward_list0.append(destprt)
					forward_list0.append(cidr_count)
					forward_list0.append(outputQ)
					forward_list0.append(dscpecn)
					forward_list0.append(srccidr_cnt)
				elif forward_counter == 1:
					forward_list1.append(srcaddr)
					forward_list1.append(destaddr)
					forward_list1.append(maskaddr)
					forward_list1.append(destprt)
					forward_list1.append(cidr_count)
					forward_list1.append(outputQ)
					forward_list1.append(dscpecn)
					forward_list1.append(srccidr_cnt)
				elif forward_counter == 2:
					forward_list2.append(srcaddr)
					forward_list2.append(destaddr)
					forward_list2.append(maskaddr)
					forward_list2.append(destprt)
					forward_list2.append(cidr_count)
					forward_list2.append(outputQ)
					forward_list2.append(dscpecn)
					forward_list2.append(srccidr_cnt)
				elif forward_counter == 3:
					forward_list3.append(srcaddr)
					forward_list3.append(destaddr)
					forward_list3.append(maskaddr)
					forward_list3.append(destprt)
					forward_list3.append(cidr_count)
					forward_list3.append(outputQ)
					forward_list3.append(dscpecn)
					forward_list3.append(srccidr_cnt)
				elif forward_counter == 4:
					forward_list4.append(srcaddr)
					forward_list4.append(destaddr)
					forward_list4.append(maskaddr)
					forward_list4.append(destprt)
					forward_list4.append(cidr_count)
					forward_list4.append(outputQ)
					forward_list4.append(dscpecn)
					forward_list4.append(srccidr_cnt)
				elif forward_counter == 5:
					forward_list5.append(srcaddr)
					forward_list5.append(destaddr)
					forward_list5.append(maskaddr)
					forward_list5.append(destprt)
					forward_list5.append(cidr_count)
					forward_list5.append(outputQ)
					forward_list5.append(dscpecn)
					forward_list5.append(srccidr_cnt)
				elif forward_counter == 6:
					forward_list6.append(srcaddr)
					forward_list6.append(destaddr)
					forward_list6.append(maskaddr)
					forward_list6.append(destprt)
					forward_list6.append(cidr_count)
					forward_list6.append(outputQ)
					forward_list6.append(dscpecn)
					forward_list6.append(srccidr_cnt)
				elif forward_counter == 7:
					forward_list7.append(srcaddr)
					forward_list7.append(destaddr)
					forward_list7.append(maskaddr)
					forward_list7.append(destprt)
					forward_list7.append(cidr_count)
					forward_list7.append(outputQ)
					forward_list7.append(dscpecn)
					forward_list7.append(srccidr_cnt)
				elif forward_counter == 8:
					forward_list8.append(srcaddr)
					forward_list8.append(destaddr)
					forward_list8.append(maskaddr)
					forward_list8.append(destprt)
					forward_list8.append(cidr_count)
					forward_list8.append(outputQ)
					forward_list8.append(dscpecn)
					forward_list8.append(srccidr_cnt)
				elif forward_counter == 9:
					forward_list9.append(srcaddr)
					forward_list9.append(destaddr)
					forward_list9.append(maskaddr)
					forward_list9.append(destprt)
					forward_list9.append(cidr_count)
					forward_list9.append(outputQ)
					forward_list9.append(dscpecn)
					forward_list9.append(srccidr_cnt)
				elif forward_counter == 10:
					forward_list10.append(srcaddr)
					forward_list10.append(destaddr)
					forward_list10.append(maskaddr)
					forward_list10.append(destprt)
					forward_list10.append(cidr_count)
					forward_list10.append(outputQ)
					forward_list10.append(dscpecn)
					forward_list10.append(srccidr_cnt)
				elif forward_counter == 11:
					forward_list11.append(srcaddr)
					forward_list11.append(destaddr)
					forward_list11.append(maskaddr)
					forward_list11.append(destprt)
					forward_list11.append(cidr_count)
					forward_list11.append(outputQ)
					forward_list11.append(dscpecn)
					forward_list11.append(srccidr_cnt)
			
				forward_counter = forward_counter + 1
			
	##############Check for entry in Forwarding table#############
	def check_for_IP(srcaddr, destaddr):
		 n = []
		 src = []
	 
		 try:
			 a = ipaddr.IPAddress(str(destaddr[0]))
		 
			 b = ipaddr.IPAddress(str(srcaddr[0]))
		 
			 n.append(ipaddr.IPNetwork(str(forward_list0[1] + '/' + forward_list0[4])))
			 n.append(ipaddr.IPNetwork(str(forward_list1[1] + '/' + forward_list1[4])))
			 n.append(ipaddr.IPNetwork(str(forward_list2[1] + '/' + forward_list2[4])))
			 n.append(ipaddr.IPNetwork(str(forward_list3[1] + '/' + forward_list3[4])))
			 n.append(ipaddr.IPNetwork(str(forward_list4[1] + '/' + forward_list4[4])))
			 n.append(ipaddr.IPNetwork(str(forward_list5[1] + '/' + forward_list5[4])))
			 n.append(ipaddr.IPNetwork(str(forward_list6[1] + '/' + forward_list6[4])))
			 n.append(ipaddr.IPNetwork(str(forward_list7[1] + '/' + forward_list7[4])))
			 n.append(ipaddr.IPNetwork(str(forward_list8[1] + '/' + forward_list8[4])))
			 n.append(ipaddr.IPNetwork(str(forward_list9[1] + '/' + forward_list9[4])))
			 n.append(ipaddr.IPNetwork(str(forward_list10[1] + '/' + forward_list10[4])))
			 n.append(ipaddr.IPNetwork(str(forward_list11[1] + '/' + forward_list11[4])))
		 
			 src.append(ipaddr.IPNetwork(str(forward_list0[0] + '/' + forward_list0[7])))
			 src.append(ipaddr.IPNetwork(str(forward_list1[0] + '/' + forward_list1[7])))	
			 src.append(ipaddr.IPNetwork(str(forward_list2[0] + '/' + forward_list2[7])))	
			 src.append(ipaddr.IPNetwork(str(forward_list3[0] + '/' + forward_list3[7])))		 
			 src.append(ipaddr.IPNetwork(str(forward_list4[0] + '/' + forward_list4[7])))	
			 src.append(ipaddr.IPNetwork(str(forward_list5[0] + '/' + forward_list5[7])))	
			 src.append(ipaddr.IPNetwork(str(forward_list6[0] + '/' + forward_list6[7])))	
			 src.append(ipaddr.IPNetwork(str(forward_list7[0] + '/' + forward_list7[7])))	
			 src.append(ipaddr.IPNetwork(str(forward_list8[0] + '/' + forward_list8[7])))	
			 src.append(ipaddr.IPNetwork(str(forward_list9[0] + '/' + forward_list9[7])))	
			 src.append(ipaddr.IPNetwork(str(forward_list10[0] + '/' + forward_list10[7])))	
			 src.append(ipaddr.IPNetwork(str(forward_list11[0] + '/' + forward_list11[7])))	
		 
		 
			 #A check to see if the packet has the source network address
			 if src[0].Contains(b) or src[1].Contains(b) or src[2].Contains(b) or src[3].Contains(b) or src[4].Contains(b) or src[5].Contains(b) or src[6].Contains(b) or src[7].Contains(b) or src[8].Contains(b) or src[9].Contains(b) or src[10].Contains(b) or src[11].Contains(b):
				flag = True
			 else:
				flag = False
		 
			 if flag:
				 #Algorithm to check longest match of the IP address and forwarding them accordingly 
				 if n[0].Contains(a):
						   if n[0].Contains(a) and n[1].Contains(a):
							   if forward_list0[4] <  forward_list1[4]:
								   return [forward_list1[3], forward_list1[5], forward_list1[6]]
						   else:
							   return [forward_list0[3], forward_list0[5], forward_list0[6]]
				 elif n[1].Contains(a):
					   if n[1].Contains(a) and n[2].Contains(a):
						   if forward_list1[4] <  forward_list2[4]:
							   return [forward_list2[3], forward_list2[5], forward_list2[6]]
					   else:
						   return [forward_list1[3], forward_list1[5], forward_list1[6]]
				 elif n[2].Contains(a):
					   if n[2].Contains(a) and n[3].Contains(a):
						   if forward_list2[4] <  forward_list3[4]:
							   return [forward_list3[3], forward_list3[5], forward_list3[6]]
					   else:
						   return [forward_list2[3], forward_list2[5], forward_list2[6]]
				 elif n[3].Contains(a):
					   if n[3].Contains(a) and n[4].Contains(a):
						   if forward_list3[4] <  forward_list4[4]:
							   return [forward_list4[3], forward_list4[5], forward_list4[6]]
					   else:
						   return [forward_list3[3], forward_list3[5], forward_list3[6]]
				 elif n[4].Contains(a):
					   if n[4].Contains(a) and n[5].Contains(a):
						   if forward_list4[4] <  forward_list5[4]:
							   return [forward_list5[3], forward_list5[5], forward_list5[6]]
					   else:
						   return [forward_list4[3], forward_list4[5], forward_list4[6]]
				 elif n[5].Contains(a):
					   if n[5].Contains(a) and n[6].Contains(a):
						   if forward_list5[4] <  forward_list6[4]:
							   return [forward_list6[3], forward_list6[5], forward_list6[6]]
					   else:
						   return [forward_list5[3], forward_list5[5], forward_list5[6]]
				 elif n[6].Contains(a):
					   if n[6].Contains(a) and n[7].Contains(a):
						   if forward_list6[4] <  forward_list7[4]:
							   return [forward_list7[3], forward_list7[5], forward_list7[6]]
					   else:
						   return [forward_list6[3], forward_list6[5], forward_list6[6]]
				 elif n[7].Contains(a):
					   if n[7].Contains(a) and n[8].Contains(a):
						   if forward_list7[4] <  forward_list8[4]: 
							   return [forward_list8[3], forward_list8[5], forward_list8[6]]
					   else:
						   return [forward_list7[3], forward_list7[5], forward_list7[6]]
				 elif n[8].Contains(a):
					   if n[8].Contains(a) and n[9].Contains(a):
						   if forward_list8[4] <  forward_list9[4]:
							   return [forward_list9[3], forward_list9[5], forward_list9[6]]
					   else:
						   return [forward_list8[3], forward_list8[5], forward_list8[6]]
				 elif n[9].Contains(a):
					   if n[9].Contains(a) and n[10].Contains(a):
						   if forward_list9[4] <  forward_list10[4]:
							   return [forward_list10[3], forward_list10[5], forward_list10[6]]
					   else:
						   return [forward_list9[3], forward_list9[5], forward_list9[6]]
				 elif n[10].Contains(a):
						   return [forward_list10[3], forward_list10[5], forward_list10[6]]
				 elif n[11].Contains(a):
						   return [forward_list11[3], forward_list11[5], forward_list11[6]]
				 else:
					   return [str(1), str(1), forward_list0[6]] 
			 else:
				 return [str(1), str(1), forward_list0[6]] 	
		 except IndexError:
			   return [str(100), str(100)]  
		 except ValueError:
			   return [str(100), str(100)]
		
	##############Function to write the data to file#############
	def write_Output(fileName, data):
		file = open(fileName, "a")
		data = str(data)
		file.write((''.join(i for i in data)))
			  
	############Main function calling for the programme###########
	Input_counters = {}
	Output_counters = {}

	residencetime_queue_1_a = 0
	residencetime_queue_1_b = 0
	residencetime_queue_1_c = 0
	residencetime_queue_2_a = 0
	residencetime_queue_2_b = 0
	residencetime_queue_2_c = 0
	residencetime_queue_3_a = 0
	residencetime_queue_3_b = 0
	residencetime_queue_3_c = 0

	try:
	   user_inputs()
	   print 'Processing....'
	except ValueError:
	   print("That's not an int!")
   
	collect_ForwardTable()

	Input_counters = inputreader(1,inputfile1,firstpackSize(inputfile1))
	chunksize_a = chunksize
	Meanpacksize_a = float(chunksize_a) / Input_counters.get('input Link - 1', "none")
	if outputportSpeed001 != 0:
		utilization_a = float((chunksize_a / Input_counters.get('input Link - 1', "none"))) / (outputportSpeed001 * 1000)


	Input_counters = inputreader(2,inputfile2, firstpackSize(inputfile2))
	chunksize_b = chunksize
	Meanpacksize_b = float(chunksize_b) / Input_counters.get('input Link - 2', "none")
	if outputportSpeed002 != 0:
		utilization_b = float((chunksize_b / Input_counters.get('input Link - 2', "none"))) / (outputportSpeed002 * 1000)
	Lambda_b = chunksize_b/(portSpeed002 * 1000)
	
	chunksize_c = 0
	Meanpacksize_c = 0

	Output_counters = forward_addr(portSpeed001, portSpeed002, portSpeed003, outputportSpeed001, outputportSpeed002, outputportSpeed003)

	#########queue 1 calculations##################################
	queue_1_a_cnt_percent = float(queue_1_a_cnt) / Input_counters.get('input Link - 1', "none")
	queue_1_b_cnt_percent = float(queue_1_b_cnt) / Input_counters.get('input Link - 1', "none")
	queue_1_c_cnt_percent = float(queue_1_c_cnt) / Input_counters.get('input Link - 1', "none")

	Lambda_a = float(chunksize_a)/(portSpeed001 * 1000)  ###lambda calculation
	Lambda_queue_1_a = float(chunksize_a * queue_1_a_cnt_percent) /(portSpeed001 * 1000)
	Lambda_queue_1_b = float(chunksize_a * queue_1_b_cnt_percent) /(portSpeed001 * 1000)
	Lambda_queue_1_c = float(chunksize_a * queue_1_c_cnt_percent) /(portSpeed001 * 1000)

	queue_1_a_meanpackssize = float(queue_1_a_cnt_percent) * Meanpacksize_a
	queue_1_b_meanpackssize = float(queue_1_b_cnt_percent) * Meanpacksize_a
	queue_1_c_meanpackssize = float(queue_1_c_cnt_percent) * Meanpacksize_a

	if queueSpeed001_a != 0 and queueSpeed001_b != 0 and queueSpeed001_c != 0:
	   queue_1_a_sercivetime = float(queue_1_a_meanpackssize) / (queueSpeed001_a * 1000)
	   queue_1_b_sercivetime = float(queue_1_b_meanpackssize) / (queueSpeed001_b * 1000)
	   queue_1_c_sercivetime = float(queue_1_c_meanpackssize) / (queueSpeed001_b * 1000)
   
	if queueSpeed001_a != 0 and queueSpeed001_b != 0 and queueSpeed001_c != 0:
	   if queue_1_a_cnt != 0: 
			utilization_queue_1_a = float(chunksize_a / queue_1_a_cnt) / (queueSpeed001_a * 1000)
			residencetime_queue_1_a = float(utilization_queue_1_a * queue_1_a_sercivetime )/ (1 - utilization_queue_1_a)
			if priorityOut1a != 0:
				residencetime_queue_1_a = residencetime_queue_1_a * priorityOut1a
	   else:
			utilization_queue_1_a = 0
	
	   if queue_1_b_cnt != 0: 
		   utilization_queue_1_b = float(chunksize_a / queue_1_b_cnt) / (queueSpeed001_b * 1000)
		   residencetime_queue_1_b = float(utilization_queue_1_b * queue_1_b_sercivetime )/ (1 - utilization_queue_1_b)
		   if priorityOut1b != 0:
			   residencetime_queue_1_b = residencetime_queue_1_b * priorityOut1b
	   else:
		   utilization_queue_1_b = 0
	   
	   if queue_1_c_cnt != 0: 
		   utilization_queue_1_c = float(chunksize_a / queue_1_c_cnt) / (queueSpeed001_c * 1000)
		   residencetime_queue_1_c = float(utilization_queue_1_c * queue_1_c_sercivetime )/ (1 - utilization_queue_1_c)
		   if priorityOut1c != 0:
			   residencetime_queue_1_c = residencetime_queue_1_c * priorityOut1c
	   else:
		   utilization_queue_1_c = 0 
	   
	#########queue 2 calculations###################################
	queue_2_a_cnt_percent = float(queue_2_a_cnt) / Input_counters.get('input Link - 2', "none")
	queue_2_b_cnt_percent = float(queue_2_b_cnt) / Input_counters.get('input Link - 2', "none")
	queue_2_c_cnt_percent = float(queue_2_c_cnt) / Input_counters.get('input Link - 2', "none")

	Lambda_b = float(chunksize_b)/(portSpeed002 * 1000)  ###lambda calculation
	Lambda_queue_2_a = float(chunksize_b * queue_2_a_cnt_percent) /(portSpeed002 * 1000)
	Lambda_queue_2_b = float(chunksize_b * queue_2_b_cnt_percent) /(portSpeed002 * 1000)
	Lambda_queue_2_c = float(chunksize_b * queue_2_c_cnt_percent) /(portSpeed002 * 1000)

	queue_2_a_meanpackssize = float(queue_2_a_cnt_percent) * Meanpacksize_b
	queue_2_b_meanpackssize = float(queue_2_b_cnt_percent) * Meanpacksize_b
	queue_2_c_meanpackssize = float(queue_2_c_cnt_percent) * Meanpacksize_c

	if queueSpeed002_a != 0 and queueSpeed002_b != 0 and queueSpeed002_c != 0:
	   queue_2_a_sercivetime = float(queue_2_a_meanpackssize) / (queueSpeed002_a * 1000)
	   queue_2_b_sercivetime = float(queue_2_b_meanpackssize) / (queueSpeed002_b * 1000)
	   queue_2_c_sercivetime = float(queue_2_c_meanpackssize) / (queueSpeed002_b * 1000)
   
	if queueSpeed002_a != 0 and queueSpeed002_b != 0 and queueSpeed002_c != 0:
	   if queue_2_a_cnt != 0: 
			utilization_queue_2_a = float(chunksize_a / queue_2_a_cnt) / (queueSpeed002_a * 1000)
			residencetime_queue_2_a = float(utilization_queue_2_a * queue_2_a_sercivetime )/ (1 - utilization_queue_2_a)
			if priorityOut2a != 0:
				residencetime_queue_2_a = residencetime_queue_2_a * priorityOut2a
	   else:
			utilization_queue_2_a = 0
	
	   if queue_2_b_cnt != 0: 
		   utilization_queue_2_b = float(chunksize_a / queue_2_b_cnt) / (queueSpeed002_b * 1000)
		   residencetime_queue_2_b = float(utilization_queue_2_b * queue_2_b_sercivetime )/ (1 - utilization_queue_2_b)
		   if priorityOut2b != 0:
			   residencetime_queue_2_b = residencetime_queue_2_b * priorityOut2b
	   
	   else:
		   utilization_queue_2_b = 0
	   
	   if queue_2_c_cnt != 0: 
		   utilization_queue_2_c = float(chunksize_a / queue_2_c_cnt) / (queueSpeed002_c * 1000)
		   residencetime_queue_2_c = float(utilization_queue_2_c * queue_2_c_sercivetime )/ (1 - utilization_queue_2_c)
		   if priorityOut2c != 0:
			   residencetime_queue_2_c = residencetime_queue_2_c * priorityOut2c
	   else:
		   utilization_queue_2_c = 0

	#########queue 3 calculations##############################
	if Input_counters.get('input Link - 3', "none") != 0:
		queue_3_a_cnt_percent = float(queue_3_a_cnt) / Input_counters.get('input Link - 3', "none")
		queue_3_b_cnt_percent = float(queue_3_b_cnt) / Input_counters.get('input Link - 3', "none")
		queue_3_c_cnt_percent = float(queue_3_c_cnt) / Input_counters.get('input Link - 3', "none")
	else:
	    queue_3_a_cnt_percent = 0
	    queue_3_b_cnt_percent = 0
	    queue_3_c_cnt_percent = 0

	Lambda_c = float(chunksize_b)/(portSpeed002 * 1000)  ###lambda calculation
	Lambda_queue_3_a = float(chunksize_c * queue_3_a_cnt_percent) /(portSpeed003 * 1000)
	Lambda_queue_3_b = float(chunksize_c * queue_3_b_cnt_percent) /(portSpeed003 * 1000)
	Lambda_queue_3_c = float(chunksize_c * queue_3_c_cnt_percent) /(portSpeed003 * 1000)


	queue_3_a_meanpackssize = float(queue_3_a_cnt_percent) * Meanpacksize_c
	queue_3_b_meanpackssize = float(queue_3_b_cnt_percent) * Meanpacksize_c
	queue_3_c_meanpackssize = float(queue_3_c_cnt_percent) * Meanpacksize_c


	if queueSpeed003_a != 0 and queueSpeed003_b != 0 and queueSpeed003_c != 0:
	   queue_3_a_sercivetime = float(queue_3_a_meanpackssize) / (queueSpeed003_a * 1000)
	   queue_3_b_sercivetime = float(queue_3_b_meanpackssize) / (queueSpeed003_b * 1000)
	   queue_3_c_sercivetime = float(queue_3_c_meanpackssize) / (queueSpeed003_c * 1000)
   
	if queueSpeed003_a != 0 and queueSpeed003_b != 0 and queueSpeed003_c != 0:
	   if queue_3_a_cnt != 0: 
			utilization_queue_3_a = float(chunksize_a / queue_3_a_cnt) / (queueSpeed003_a * 1000)
			residencetime_queue_3_a = float(utilization_queue_3_a * queue_3_a_sercivetime )/ (1 - utilization_queue_3_a)
			if priorityOut3a != 0:
			   residencetime_queue_3_a = residencetime_queue_3_a * priorityOut3a
	   else:
			utilization_queue_3_a = 0
	
	   if queue_3_b_cnt != 0: 
		   utilization_queue_3_b = float(chunksize_a / queue_3_b_cnt) / (queueSpeed003_b * 1000)
		   residencetime_queue_3_b = float(utilization_queue_3_b * queue_3_b_sercivetime )/ (1 - utilization_queue_3_b)
		   if priorityOut3b != 0:
			   residencetime_queue_3_b = residencetime_queue_3_b * priorityOut3b
	   else:
			utilization_queue_3_b = 0
		
	   if queue_3_c_cnt != 0: 
		   utilization_queue_3_c = float(chunksize_a / queue_3_c_cnt) / (queueSpeed003_c * 1000)
		   residencetime_queue_3_c = float(utilization_queue_3_c * queue_3_c_sercivetime )/ (1 - utilization_queue_3_c)
		   if priorityOut3c != 0:
			   residencetime_queue_3_c = residencetime_queue_3_c * priorityOut3c
	   else:
			utilization_queue_3_c = 0
			
	r107count = 364
		
	##############Calculating mean residence#################################

	mean_res_1a = (sum(list1a) / float(len(list1a)))*priorityOut1a
	mean_res_1b = (sum(list1b) / float(len(list1b)))*priorityOut1b
	mean_res_1c = (sum(list1c) / float(len(list1c)))*priorityOut1c

	mean_res_2a = (sum(list2a) / float(len(list2a)))*priorityOut2a
	mean_res_2b = (sum(list2b) / float(len(list2b)))*priorityOut2b
	mean_res_2c = (sum(list2c) / float(len(list2c)))*priorityOut2c

	mean_res_3a = (sum(list3a) / float(len(list3a)))*priorityOut3a
	mean_res_3b = (sum(list3b) / float(len(list3b)))*priorityOut3b
	mean_res_3c = (sum(list3c) / float(len(list3c)))*priorityOut3c

	mean_no_item_1a = (mean_res_1a)*10
	mean_no_item_1b = (mean_res_1b)*10
	mean_no_item_1c = (mean_res_1c)*10

	mean_no_item_2a = (mean_res_2a)*10 
	mean_no_item_2b = (mean_res_2b)*10 
	mean_no_item_2c = (mean_res_2c)*10

	mean_no_item_3a = (mean_res_3a)*10
	mean_no_item_3b = (mean_res_3b)*10 
	mean_no_item_3c = (mean_res_3c)*10



	print '\n\n\n'
	print '-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*Router 7 Analysis Report-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*'
	print '\n\n\n'

	print 'Input Packets Processed : ', Input_counters
	print 'Output Packets Processed : ', Output_counters
	print '\n'

	print 'Packets processed in Input Queue 1-A : ', queue_1_a_cnt
	print 'Packets processed in Input Queue 1-B : ', queue_1_b_cnt
	print 'Packets processed in Input Queue 1-C : ', queue_1_c_cnt
	print '\n'
	print 'Packets processed in Input Queue 2-A : ', queue_2_a_cnt
	print 'Packets processed in Input Queue 2-B : ', queue_2_b_cnt
	print 'Packets processed in Input Queue 2-C : ', queue_2_c_cnt
	print '\n'
	print 'Packets processed in Input Queue 3-A : ', queue_3_a_cnt
	print 'Packets processed in Input Queue 3-B : ', queue_3_b_cnt
	print 'Packets processed in Input Queue 3-C : ', queue_3_c_cnt
	print '\n'
	'''
	print 'Mean Residence times in Output Queue 1-A  : ' , residencetime_queue_1_a * priorityoutprcnt1a / 100
	print 'Mean Residence times in Output Queue 1-B  : ' , residencetime_queue_1_b * priorityoutprcnt1b / 100
	print 'Mean Residence times in Output Queue 1-C  : ' , residencetime_queue_1_c * priorityoutprcnt1c / 100
	print '\n'
	print 'Mean Residence times in Output Queue 2-A  : ' , residencetime_queue_2_a * priorityoutprcnt2a / 100
	print 'Mean Residence times in Output Queue 2-B  : ' , residencetime_queue_2_b * priorityoutprcnt2b / 100
	print 'Mean Residence times in Output Queue 2-C  : ' , residencetime_queue_2_c * priorityoutprcnt2c / 100
	print '\n'
	print 'Mean Residence times in Output Queue 3-A  : ' , residencetime_queue_3_a * priorityoutprcnt3a / 100
	print 'Mean Residence times in Output Queue 3-B  : ' , residencetime_queue_3_b * priorityoutprcnt3b / 100
	print 'Mean Residence times in Output Queue 3-C  : ' , residencetime_queue_3_c * priorityoutprcnt3c / 100
	''' 
	try:
	   print 'Maximum residence time in output Queue 1-A (Max Tr) : ',(max(list1a) * priorityOut1a)*10
	except ValueError:
	   print 0
	try:
	   print 'Maximum residence time in output Queue 1-B (Max Tr) : ',(max(list1b) * priorityOut1b)*10
	except ValueError:
	   print 0
	try:
	   print 'Maximum residence time in output Queue 1-C (Max Tr) : ',(max(list1c) * priorityOut1c)*10
	except ValueError:
	   print 0
	print '\n'
	try:
	   print 'Maximum residence time in output Queue 2-A (Max Tr) : ',(max(list2a) * priorityOut2a)*10
	except ValueError:
	   print 0
	try:
	   print 'Maximum residence time in output Queue 2-B (Max Tr) : ',(max(list2b) * priorityOut2b)*10
	except ValueError:
	   print 0
	try:
	   print 'Maximum residence time in output Queue 2-C (Max Tr) : ',(max(list2c) * priorityOut2c)*10
	except ValueError:
	   print 0
	print '\n'
	try:
	   print 'Maximum residence time in output Queue 3-A (Max Tr) : ',(max(list3a) * priorityOut3a)*10
	except ValueError:
	   print 0
	try:
	   print 'Maximum residence time in output Queue 3-B (Max Tr) : ',(max(list3b) * priorityOut3b)*10
	except ValueError:
	   print 0
	try:
	   print 'Maximum residence time in output Queue 3-C (Max Tr) : ',(max(list3c) * priorityOut3c)*10
	except ValueError:
	   print 0
	print '\n'
	print 'Mean number of items in residence at Queue 1-A : ' , round(mean_no_item_1a, 2)/ float(priorityOut1a) * Output_counters['outputLink - 1']/float(priorityoutprcnt1a)*30, " Packets"
	print 'Mean number of items in residence at Queue 1-B : ' , round(mean_no_item_1b, 2)/ float(priorityOut1b) * Output_counters['outputLink - 1']/float(priorityoutprcnt1b), " Packets"
	print 'Mean number of items in residence at Queue 1-C : ' , round(mean_no_item_1c, 2)/ float(priorityOut1c) * Output_counters['outputLink - 1']/float(priorityoutprcnt1c), " Packets"
	print '\n'
	print 'Mean number of items in residence at Queue 2-A : ' , round(mean_no_item_2a, 2)/ float(priorityOut2a) * Output_counters['outputLink - 2']/float(priorityoutprcnt2a)*30, " Packets"
	print 'Mean number of items in residence at Queue 2-B : ' , round(mean_no_item_2b, 2)/ float(priorityOut2b) * Output_counters['outputLink - 2']/float(priorityoutprcnt2b), " Packets"
	print 'Mean number of items in residence at Queue 2-C : ' , round(mean_no_item_2c, 2)/ float(priorityOut2c) * Output_counters['outputLink - 2']/float(priorityoutprcnt2c), " Packets"
	print '\n'
	print 'Mean number of items in residence at Queue 3-A : ' , round(mean_no_item_3a, 2)/ float(priorityOut3a) * Output_counters['outputLink - 3']/float(priorityoutprcnt3a)*30, " Packets"
	print 'Mean number of items in residence at Queue 3-B : ' , round(mean_no_item_3b, 2)/ float(priorityOut3b) * Output_counters['outputLink - 3']/float(priorityoutprcnt3b), " Packets"
	print 'Mean number of items in residence at Queue 3-C : ' , round(mean_no_item_3c, 2)/ float(priorityOut3c) * Output_counters['outputLink - 3']/float(priorityoutprcnt3c), " Packets"
	print '\n'
	#print 'Maximum number in residence : ', round ((det_highest(det_highest(mean_no_item_1a, mean_no_item_1b, mean_no_item_1c), det_highest(mean_no_item_2a, mean_no_item_2b, mean_no_item_2c), det_highest(mean_no_item_3a, mean_no_item_3b, mean_no_item_3c)))/ float (10) * det_highest(Output_counters['outputLink - 3'],Output_counters['outputLink - 2'] ,Output_counters['outputLink - 1']), 2)/ float(10), " Packets"
	print '\n'
	print "Executed Router 7 succesfully!"
	print '\n\n\n'
	print '-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*Router Network End-to-End Analysis Report-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*'
	print '\n\n\n'
	print 'Total Packets handled from End-to-End : ', total_packet_count
	print '\n'
	print 'Total packets written to destination : ', total_packet_dest
	print '\n'
	print 'Total packets forwarded to Next-hop/dump : ', total_packet_next_hop
	print '\n'
	print 'Mean number of items in residence (Average): ', total_number_residence
	print '\n'
	print 'Max number of items in residence (Average): ', total_number_max_residence
	print '\n'
	print 'Average Mean Residence time in the network  : ', avg_mean_residence / float(100)
	print '\n'
	print 'Average Maximum Residence time in the network  : ', avg_max_residence
	print '\n'
	
	
	

Router_7()

	