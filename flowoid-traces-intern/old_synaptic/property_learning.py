from pyretic.synaptic.formal.logic import *
from pyretic.synaptic.support.database import *
from pyretic.synaptic.support import stats
from pyretic.synaptic.support import util
from xml.dom import minidom
import networkx

# list of dangerous permissions

dangerous_permissions = {
'android.permission.ADD_VOICEMAIL': True, 
'android.permission.USE_SIP': True, 
'android.permission.RECORD_AUDIO': True, 
'android.permission.READ_EXTERNAL_STORAGE': True, 
'android.permission.BODY_SENSORS': True, 
'android.permission.SEND_SMS': True, 
'android.permission.ACCESS_COARSE_LOCATION': True, 
'android.permission.ACCESS_FINE_LOCATION': True, 
'android.permission.READ_CALENDAR': True, 
'android.permission.CAMERA': True, 
'android.permission.WRITE_CALENDAR': True, 
'android.permission.WRITE_CONTACTS': True, 
'android.permission.PROCESS_OUTGOING_CALLS': True, 
'android.permission.CALL_PHONE': True, 
'android.permission.RECEIVE_MMS': True, 
'android.permission.READ_CALL_LOG': True, 
'android.permission.GET_ACCOUNTS': True, 
'android.permission.READ_SMS': True, 
'android.permission.RECEIVE_SMS': True, 
'android.permission.RECEIVE_WAP_PUSH': True, 
'android.permission.WRITE_EXTERNAL_STORAGE': True, 
'android.permission.WRITE_CALL_LOG': True, 
'android.permission.READ_CONTACTS': True, 
'android.permission.READ_PHONE_STATE': True
}



# class learning the properties required by an application

class PropertyLearner (object) :

	def __init__ (self, pt=None, at=None, ut=None) :
		self.__net_model = None
		self.__ip_stats = dict()
		self.__port_stats = dict()
		self.__permissions = list()
		self.__properties = set()
		self.__avg_interval = 0.0

# read the different thresholds for learning properties

		self.__probability_threshold = pt if pt!=None else read_synaptic_probability_threshold()
		self.__attack_threshold = at if at!=None else read_synaptic_attack_threshold()
		self.__unsafeness_threshold = ut if ut!=None else read_synaptic_unsafeness_threshold()
		super(PropertyLearner, self).__init__()

	@property
	def net_model (self) :
		return self.__net_model

	@net_model.setter
	def net_model (self, net_model) :
		self.__net_model = net_model

	@property
	def ip_stats (self) :
		return self.__ip_stats

	@ip_stats.setter
	def ip_stats (self, ip_stats) :
		self.__ip_stats = ip_stats

	@property
	def properties (self) :
		return self.__properties

	@property
	def permissions (self) :
		return list(self.__permissions)

	@property
	def avg_interval (self) :
		return self.__avg_interval

	@avg_interval.setter
	def avg_interval (self, avg_interval) :
		self.__avg_interval = avg_interval

	@property
	def attack_threshold (self) :
		return self.__attack_threshold

	@attack_threshold.setter
	def attack_threshold (self, attack_threshold) :
		self.__attack_threshold = attack_threshold

	@property
	def probability_threshold (self) :
		return self.__probability_threshold

	@probability_threshold.setter
	def probability_threshold(self, probability_threshold) :
		self.__probability_threshold = probability_threshold

	@property
	def unsafeness_threshold (self) :
		return self.__unsafeness_threshold

	@unsafeness_threshold.setter
	def unsafeness_threshold (self, unsafeness_threshold) :
		self.__unsafeness_threshold = unsafeness_threshold

# clear the property learner between two learnings

	def clear (self) :
		self.__net_model = None
		self.__ip_stats = dict()
		self.__permissions = list()
		self.__properties = set()

# load a manifest file and its internal permissions

	def load_manifest (self, manifest) :

# load the manifest file and extract its permissions

		f = open(manifest)
		manifest = f.read()
		f.close()

		manifest = minidom.parseString(manifest)
		manifest = manifest.firstChild
		permissions = manifest.getElementsByTagName('uses-permission')
# add all permissions in the corresponding list

		for p in permissions :
			name = p.attributes['android:name']
			self.__permissions.append(str(name.value))

# load permissions from the database

	def load_permissions (self, application) :
		if application in PermissionDB :
			self.__permissions = PermissionDB[application]

# method for learning properties from an automata

	def learn (self) :
		self.__learn_dangerous_permissions()
		self.__learn_mass_attacks()
#		self.__learn_botnet_traffic()
		self.__learn_unsafe_ips()
		self.__learn_safe_ips()
		self.__learn_protocols()

# learn the dangerous permissions to filter

	def __learn_dangerous_permissions (self) :
		for permission in self.__permissions :
			if dangerous_permissions.has_key(permission) :
				property = dangerous(permission=permission)
				self.__properties.add(property)

# learn the safe ip address

	def __learn_safe_ips(self) :

# if an ip address has not been classified as unsafe or malicious, classify it as safe

		for ip in self.__ip_stats :
			if ip==IP('10.10.0.1') : continue
			if self.__ip_stats[ip].flags == 0 :
				property = Safe(IP(ip))
				self.__properties.add(property)

# learn the unsafe ip address to filter more specifically

	def __learn_unsafe_ips(self) :

# if the ranking of an ip is greater than the unsafeness threshold, classify it as unsafe

		for ip in self.__ip_stats :
			if ip==IP('10.10.0.1') : continue
			if self.__ip_stats[ip].flags != 0 : continue
			elif self.__ip_stats[ip].ranking>=self.__unsafeness_threshold :
				self.__ip_stats[ip].flags |= util.unsafe
				property = Unsafe(IP(ip))
				self.__properties.add(property)

# learn the dos and port scanning traffic in the automaton

	def __learn_mass_attacks(self) :

# search for over probable loops

		suspicious = list()
		automaton = self.__net_model

#		for n in automaton :
#			if n in automaton.edge[n] :
#				if automaton.edge[n][n]['label']>self.__probability_threshold :
#					suspicious.append(n)

# search for over-probables IP in the states classified as suspicious

		for n in automaton.nodes() :
			if automaton.node[n]['label'] in {'INITIAL', 'TERMINAL'} : continue
			flows = automaton.node[n]['logs']
			ips = stats.count([f[1] for f in flows])
			malicious_ips = filter(lambda ip:ips[ip]>self.__attack_threshold, ips)

# if the ip is contacted less often than the specified threshold discard it

			for ip in malicious_ips :
				attack_flows = filter(lambda f:f[1]==ip and not f[2] in {'80', '443'} and f[5]<=2, flows)
				ports = {f[2] for f in attack_flows}

# if there is to many port numbers classify the traffic as port scanning

				if len(ports)>self.__attack_threshold :
					flow = attack_flows[0]
					p = PortScanning(IP(flow[1]))
					self.__properties.add(p)
					self.__ip_stats[ip].flags |= util.port_scanning

# otherwise classify it as dos

				else :
					continue
					flow = attack_flows[0]
					p = DOS(IP(ip))
					self.__properties.add(p)
					self.__ip_stats[ip].flags |= util.dos

# does the same job for port numbers

			return
			ports = stats.count([f[2] for f in flows])
			if ports.has_key(80) : ports.pop(80)
			if ports.has_key(443) : ports.pop(443)
			malicious_ports = filter(lambda port:ports[port]>self.__attack_threshold, ports)

# if the port is contacted less often than the specified threshold discard it

			for port in malicious_ports :
				attack_flows = filter(lambda f:f[2]==port and f[5]<=2, flows)
				if len(attack_flows)<3 : continue
				intervals = [attack_flows[i][0]-attack_flows[i-1][0] for i in range(1,len(attack_flows))]
				if sum(intervals)/len(intervals)>self.__avg_interval : continue

# create the property and record it

				min_ip = min([IP(f[1]) for f in attack_flows])
				min_ip = min_ip.bits.to01()

				max_ip = max([IP(f[1]) for f in attack_flows])
				max_ip = max_ip.bits.to01()

				prefix = os.path.commonprefix({min_ip, max_ip})
				masklen = len(prefix)
				prefix += '0'*(32-masklen)

				ip = IP('0.0.0.0')
				ip.bits = bitarray(prefix)
				prefix = str(ip)+'/'+str(masklen)

# compute and add the property

#				flow = attack_flows[0]
				p = Worm(int(port))
				print p
				exit()
				self.__properties.add(p)
				for f in attack_flows : self.__ip_stats[f[1]].flags |= util.worm

# learn the botnet traffic in the automaton

	def __learn_botnet_traffic(self) :

# for each state of the automaton

		for s in self.__net_model.node :
			if self.__net_model.node[s]['label'] in {'INITIAL', 'TERMINAL'} : continue
			logs = self.__net_model.node[s]['logs']
			if len(logs) <= 1 : continue
			inter_arrival = self.__net_model.node[s]['avg_interarival']
			protocols = self.__net_model.node[s]['protocols']

# if none UDP/TCP traffic is detected check the destination

			if len(protocols-{'TCP','UDP'})>0 or inter_arrival<self.__avg_interval :
				ips = stats.count([f[1] for f in logs])
				malicious_ips = filter(lambda ip:ips[ip]>self.__attack_threshold, ips)

# if it is over-present classify the traffic as botnet

				for ip in malicious_ips :
					p = BotNet(IP(ip))
					self.__properties.add(p)
					self.__ip_stats[ip].flags |= util.botnet

# learn the protocols associated with each IP address

	def __learn_protocols (self) :

		for n in self.__net_model.node :

			if self.__net_model.node[n]['label'] in {"INITIAL", "TERMINAL"} :
				continue

# learn tcp flows

			tcp_flows = filter(lambda f:f[3].upper()=='TCP', self.__net_model.node[n]['logs'])
			properties = {TCP(IP(flow[1]), int(flow[2])) for flow in tcp_flows}
			self.__properties |= properties

# learn udp flows

			udp_flows = filter(lambda f:f[3].upper()=='UDP', self.__net_model.node[n]['logs'])
			properties = {UDP(IP(flow[1]), int(flow[2])) for flow in udp_flows}
			self.__properties |= properties

# learn http flows

			http_flows = filter(lambda f:f[2]=='80', self.__net_model.node[n]['logs'])
			properties = {HTTP(IP(flow[1])) for flow in http_flows}
			self.__properties |= properties

# finally learn https flows

			https_flows = filter(lambda f:f[2]=='443', self.__net_model.node[n]['logs'])
			properties = {HTTPS(IP(flow[1])) for flow in https_flows}
			self.__properties |= properties