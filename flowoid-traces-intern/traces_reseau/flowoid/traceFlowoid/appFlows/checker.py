import sys
import csv
cpt = 0
with open(sys.argv[1],"r") as csvfile:
        csvreader = csv.reader(csvfile)
	for line in csvreader:
		if (line[2]=='10.10.0.1' or line[4]=='10.10.0.1'):
			cpt=cpt+1		
		else:
			print line
print cpt	
