import sys
import csv
# import dateutil.parser
import datetime
from IPy import IP
first = True
allfeatures = ['timestamp','appname','dstaddr','dstport','srcaddr','srcport','protocol','bytes','packets']
features = ['srcaddr','srcport','dstaddr','dstport','protocol','bytes','packets','starttime','endtime']
names = []
myformat = "%Y-%m-%dT%H:%M:%S.%fZ"
epoch = datetime.datetime(1970, 1, 1)
#print ','.join(allfeatures)
dummyaddr = '10.10.0.1'
mobileaddr = ['100.121.103.121','100.83.77.164','100.106.110.143','100.120.180.206']
with open(sys.argv[1],"r") as csvfile:
	csvreader = csv.reader(csvfile)
	data= []
	for line in csvreader:
		if (first == True):
			names = line
			first = False
		else:
			row =[]
			indexes = [names.index(k) for k in features]
			#row.append(dateutil.parser.parse(line[0]).strftime("%s"))
			mydt = datetime.datetime.strptime(line[0], myformat)
			val = (mydt - epoch).total_seconds()
			row.append(repr(val))
			for i in indexes:
				if (names[i] == 'srcaddr' or names[i] == 'dstaddr'):
					# check if the addr is private
					ip = IP(line[i])
					if (ip.iptype() == 'PRIVATE' or line[i].startswith('152.81') or line[i] in mobileaddr):
						line[i] = dummyaddr
				row.append(line[i])
			data.append(row)	

data.sort(key=lambda s: (s[0]))			
for d in data:
	print(','.join(d))
	
		





