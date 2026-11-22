#!/bin/bash

# Enable strict mode
set -euo pipefail
IFS=$'\n\t'


if [ $# != 1 ]; then
  echo "USAGE: $0 CSV_FILE"
  exit 1
fi

CSV_FILE=$1
NAME=$(basename $CSV_FILE .csv)

if [[ ! -f $CSV_FILE ]]; then
  echo "Invalid input file"
  exit 1
fi


# Extract IPs
IPS=$(cut -d "," -f 3,5 $CSV_FILE | tr "," "\n" | sort | uniq)

# Reverse DNS
rm -f ${NAME}_rdns.txt
echo $IPS | sed -E "s/(\S*)+\s*/-x \1\n/g"| xargs dig +noall +answer >> ${NAME}_rdns.txt

# Whois
rm -f ${NAME}_whois.txt
for ip in $IPS; do whois $ip | grep -i netname | grep -E "\S*\s*$" -o | tr "\n" "," | sed -E "s/,$/\n/" | xargs printf "%s: %s\n" $ip >> ${NAME}_whois.txt; done