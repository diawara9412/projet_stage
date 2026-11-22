from pyretic.synaptic.support import port_prefix
from pyretic.synaptic.support import database
from pyretic.synaptic.support import graph
from pyretic.synaptic.support import stats
from pyretic.synaptic.support.util import *
from pyretic.synaptic.support import logs
from pyretic.core.language import *

import subprocess
import bgpranking_web
import networkx
import os
import re

# process miner of synaptic

class ProcessLearner (object) :
	def __init__ (self) :
		self.__net_logs = list()
		self.__sys_logs = list()
		self.__net_model = networkx.DiGraph()
		self.__net_global_fields = dict()
		self.__sys_model = networkx.DiGraph()
		self.__sys_global_fields = dict()
		self.__ip_stats = dict()
		self.__port_stats = dict()
		self.__asns = dict()
		self.__avg_interval = 0.0
		self.__flow_rate = read_synaptic_flow_rate()
		super(ProcessLearner, self).__init__()

	@property
	def net_logs (self) :
		return self.__net_logs

	@property
	def net_model (self) :
		return self.__net_model

	@property
	def net_global_fields (self) :
		return self.__net_global_fields


	@property
	def sys_logs (self) :
		return self.__sys_logs

	@property
	def sys_model (self) :
		return self.__sys_model

	@property
	def sys_global_fields (self) :
		return self.__sys_global_fields

	@property
	def ip_stats (self) :
		if self.__ip_stats.has_key(IP('10.10.0.1')) : 
			del self.__ip_stats[IP('10.10.0.1')]
		return self.__ip_stats

	@property
	def port_stats (self) :
		return self.__port_stats

	@property
	def avg_interval (self) :
		return self.__avg_interval

# clear the process learner between two iterations

	def clear (self) :
		self.__net_logs = list()
		self.__sys_logs = list()
		self.__net_model = networkx.DiGraph()
		self.__net_global_fields = dict()
		self.__sys_model = networkx.DiGraph()
		self.__sys_global_fields = dict()
		self.__ip_stats = dict()
		self.__port_stats = dict()
		self.__asns = dict()

# load the logs given in a specific file

	def load_logs (self, logfile) :

# check that the file exists

		if not os.path.exists(logfile) :
			raise IOError (logfile+" does not exists")

# load the logs in the corresponding field

		if re.match('.*\.csv$', logfile) :
			self.__net_logs = logs.load_csv_logs(logfile, self.__flow_rate)
			intervals = [self.__net_logs[i][0]-self.__net_logs[i-1][0] for i in range(1, len(self.__net_logs))]
			self.__avg_interval = sum(intervals)/len(intervals)
		elif re.match('.*\.json$', logfile) :
			self.__sys_logs = logs.load_json_logs(logfile)
		else :
			raise TypeError ("Bad file extension : "+logfile)

# load the ips describing the application from the database

	def load_stats (self) :

# raise an error in case where no logs were loaded

		if len(self.__net_logs)==0 :
			raise ValueError("You must load logs before calling this method.")
		else :
			self.__classify_net_logs()

# load the ip infos from the database

		for i in range(len(self.__net_logs)) :
			ip = self.__net_logs[i][1]
			port = self.__net_logs[i][2]
			if not ip in self.__ip_stats : self.__ip_stats[ip] = database.IpDB[str(ip)]
			if not ip in self.__port_stats : self.__port_stats[ip] = set()
			if not port in self.__port_stats[ip] : self.__port_stats[ip].add(port)
			self.__net_logs[i].append(self.__ip_stats[ip].orgname)

# add the netnames if they appear more then the selected threshold

		netnames = [str(self.__ip_stats[ip].netname) for ip in self.__ip_stats]
		netnames = stats.count(netnames)
		del netnames['None']
		n = read_synaptic_netname_significativity()

		for i in range(len(self.__net_logs)) :
			ip = self.__net_logs[i][1]
			ip_stats = self.__ip_stats[ip]
			if ip_stats.netname is None : continue
			if netnames[ip_stats.netname] > n : self.__net_logs[i][-1]= ip_stats.netname

# as second step of aggregation aggregate orgnames if the application is diverse enough

		orgname_significativity = read_synaptic_orgname_significativity ()
		orgname_diversity = read_synaptic_orgname_diversity ()
		orgnames = stats.count([flow[-1] for flow in self.__net_logs])

		if len(orgnames)>=orgname_diversity :
			for i in range(len(self.__net_logs)) :
				orgname = self.__net_logs[i][-1]
				if orgnames[orgname]<=orgname_significativity :
					self.__net_logs[i][-1] = 'others'

# finally aggregates the port numbers and return

#		self.__aggregate_port_numbers()
#			print self.__net_logs[i][-1]
		return

# compute the interesting aggregates in a log

	def compute_aggregates (self, ) :

# raise an exception if no log has been loaded

		if len(self.__net_logs)==0 :
			raise ValueError('You must load net logs before calling this method.')

# compute the aggregates

		self.__classify_net_logs()
		self.__compute_stats()
		self.__aggregate_ip_addresses()
		self.__aggregate_port_numbers()

# learn the statistics about IP addresses before storing them into the database

	def learn_ip_stats (self) :
		self.__classify_net_logs()
		self.__compute_stats()

# learn the net automaton representing the application

	def learn_net_model (self) :
		labels = logs.build_labels(self.__net_logs, [-1])
		self.__net_model = graph.generate_automaton(labels, self.__net_logs)

	def learn_sys_model (self) :
		self.__classify_sys_logs()
		self.learn_sys_automaton()


# write the net model into a text file

	def print_net_model (self) :
		f = open ('net_model.dot', 'w')
		f.write(graph.print_automaton(self.__net_model))
		f.close()

# write the sys model into a text file
	def print_sys_model (self) :
		f = open ('sys_model.dot', 'w')
		f.write(graph.print_automaton(self.__sys_model))
		f.close()

# hide the source addresses of the logs

	def __classify_net_logs(self) :

		self.__net_global_fields['resource'] = self.__net_logs[0][1]
		d={}
		n=0
		smartphone = IP('10.10.0.1')

# label each flow with the corresponding sequence number

		for i in range(len(self.__net_logs)) :
			idx = self.__net_logs[i].index(smartphone)
			port=self.__net_logs[i][idx+1]
			self.__net_logs[i].remove(smartphone)
			self.__net_logs[i].remove(port)
			del self.__net_logs[i][1]

			if idx==2 : self.__net_logs[i].append('IN')
			else : self.__net_logs[i].append('OUT')

			if port in d :
				self.__net_logs[i].append(str(d[port]))
				del d[port]
			else :
				self.__net_logs[i].append(str(n))
				if self.__net_logs[i][4]=='TCP' : d[port] = n
				n += 1

# compute the global fields of the sys model

	def __classify_sys_logs(self) :

		self.__sys_global_fields['deviceid'] = self.__sys_logs[0]['deviceid']
		self.__sys_global_fields['buildid'] = self.__sys_logs[0]['buildid']


# suppress the global fields from the sys_logs

		for s in self.__sys_logs :
			del s['deviceid']
			del s['buildid']
			del s['rowid']
			del s['latitude']
			del s['longitude']
			del s['location']
			del s['datetime']

# compute statistics about ip addresses

	def __compute_stats(self) :

# count the number of ip addresses and port numbers

		ip_counters = stats.count([log[1] for log in self.__net_logs])
		self.__port_stats = stats.count([log[2] for log in self.__net_logs])

# lookup for the asn of the ip address

		for ip in ip_counters :
			res = bgpranking_web.ip_lookup(ip)
			asn = None
			try : asn = res['history'][-1]['asn']
			except : pass

# if it isn't already known, compute its bgp ranking

			if not (asn is None or asn in self.__asns) :
				history = bgpranking_web.all_ranks_single_asn(asn)
				ranking = history.keys()[-1]
				self.__asns[asn]=history[ranking]['total']

# create and store the ip_stats object

			ip_stats = stats.IPStats()
			ip_stats.count = ip_counters[ip]
			if not asn is None : ip_stats.ranking = self.__asns[asn]
			self.__ip_stats[ip] = ip_stats

# load the stats from the database


# __aggregate the ip addresses of the log

	def __aggregate_ip_addresses(self) :

		netnames = dict()
		orgnames = dict()
		counters = dict()
		n = read_synaptic_netname_significativity()

# resolve the host names and add it to the corresponding log line

		for i in range(len(self.__net_logs)) :
			ip = self.__net_logs[i][1]

			if ip in orgnames :
				if ip in netnames :
					netname = netnames[ip]
					counters[netname] += 1
				continue

			p = subprocess.Popen("whois "+ip, stdout=subprocess.PIPE, 		stderr=subprocess.PIPE, shell=True) 
			out, err = p.communicate()

# compute the netname corresponding to the ip if any

			if "netname" in out :
				netname = out.split("\n")
				netname = filter(lambda x:"netname" in x, netname)[0]
				netname = netname.split("        ")[1]
				if ',' in netname : netname = netname.replace(',', '.')
				netnames[ip] = netname
				if self.__ip_stats[ip].netname is None : self.__ip_stats[ip].netname=netname
				if netname in counters : counters[netname] += 1
				else : counters[netname] = 1

# compute the orgname corresponding to the ip

			if "OrgName" in out :
				orgname = out.split("\n")
				orgname = filter(lambda x:"OrgName" in x, orgname)[0]
				orgname = orgname.split("        ")[1]
				if ',' in orgname : orgname = orgname.replace(',', '.')
				orgnames[self.__net_logs[i][1]] = orgname
			else :
				try :
					orgname = out.split('\n')[23]
					orgname = orgname.split(' ')
					orgname = orgname[0]+' '+orgname[1]
				except :
					orgname = database.IpDB[ip].orgname
				if ',' in orgname : orgname = orgname.replace(',', '.')
				orgnames[ip] = orgname
				if self.__ip_stats[ip].orgname is None : self.__ip_stats[ip].orgname=orgname


# append the corresponding netname/orgname to each line based on the frequencies of apparition

		for i in range(len(self.__net_logs)) :
			ip = self.__net_logs[i][1]
			netname = netnames[ip] if ip in netnames else None

			if netname is None :
				orgname = orgnames[ip]
				self.__net_logs[i].append(orgname)
			else :
				if counters[netname]>n :
					self.__net_logs[i].append(netname)
				else :
					orgname = orgnames[ip]
					self.__net_logs[i].append(orgname)


# __aggregate the port numbers of the log

	def __aggregate_port_numbers(self) :

# if there is only http and https traffic, cancel this step

		ports = [str(val[2]) for val in self.__net_logs]
		if len(stats.count(ports))==2 : return

# initialize the variables

		n = read_synaptic_port_numbers_significativity()
		bound=2
		http = {"80", "443"}
		prefixes=[]
		
	# compute the prefixes
	
		for port in ports :
			if port in http : continue
			found=False
			for p in prefixes :
				if p[0]==port : 
					found = True
					p[1]+=1
					break
				elif len(port)<p[0].masklen :
					continue
				i=0
				while port[i]==p[0].prefix[i] and i<p[0].masklen : i+=1
				if i>bound :
					p[0]=port_prefix.PortPrefix(port[:i]+'/'+str(i))
					p[1] += 1
					found=True
					break
			if not found : 
				prefixes.append([port_prefix.PortPrefix(str(port)+'/'+str(len(str(port)))),0])
	
	# replace the IP addresses by their corresponding prefixes
	
		prefixes = dict(prefixes)
		prefixes = filter(lambda x:prefixes[x]>n,prefixes)
	
		for i in range(len(ports)) :
			if ports[i] in http : 
				self.__net_logs[i].append(ports[i])
				continue
			found = False
			for p in prefixes :
				if p==ports[i] :
					if p.masklen<5 : self.__net_logs[i].append(str(p))
					else : self.__net_logs[i].append(ports[i])
					found = True
					break
			if not found :
				self.__net_logs[i].append('*')

# learn the sys automaton representing the application

	def learn_sys_automaton(self) :
		labels = logs.build_labels(self.__sys_logs, ["component"])
		self.__sys_model = graph.generate_automaton(labels, self.__sys_logs)
