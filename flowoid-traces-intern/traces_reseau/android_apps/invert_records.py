#! /usr/local/bin/python2

from pyretic.synaptic.orchestration.process_learning import *
from pyretic.synaptic.support.database import IpDB
import sys

# load the ips of the log file given as argument

learner = ProcessLearner()
learner.load_logs(sys.argv[-1])
learner.load_stats()
ip_stats = learner.ip_stats
print len(ip_stats)

for ip in ip_stats :
	print ip_stats[ip].netname, ip_stats[ip].orgname
	if ip_stats[ip].netname == 'RIPE Network Coordination Centre' :
		tmp = ip_stats[ip].netname
		ip_stats[ip].netname = ip_stats[ip].orgname
		ip_stats[ip].orgname = tmp
		IpDB[str(ip)] = ip_stats[ip]