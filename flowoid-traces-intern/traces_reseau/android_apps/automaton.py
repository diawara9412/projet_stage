#! /usr/local/bin/python2

from pyretic.synaptic.orchestration.process_learning import *
import getopt
import sys

args = sys.argv[1:]
opts, args = getopt.getopt(args,'t:')
opts = dict(opts)
threshold = int(opts['-t']) if '-t' in opts else 0
learner = ProcessLearner()
learner.load_logs(sys.argv[-1])
learner.load_stats()
learner.learn_net_model()
net_model = learner.net_model
nodes = net_model.node
nodes = filter(lambda n:nodes[n]['label']!='INITIAL' and nodes[n]['label']!='TERMINAL', nodes)
small_nodes = filter(lambda n:len(net_model.node[n]['logs'])<=threshold, nodes)
print len(nodes), (100*len(small_nodes))/len(nodes)