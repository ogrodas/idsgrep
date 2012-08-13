===========
IDSGrep
===========

Installation
=========
python setup.py install


Overview
=========
IDSGrep is a simple grep that understands: IP-addresses, CIDRs, IP-ranges and Domains. The purpose of IDSGrep is to make it easy to search large logfiles for matches in common balcklists/watchlists

IDSGrep uses GNU grep implementation of the Commentz-Walter[1] string search algorithm behind the scene. This makes it possible for IDSGrep to search large log files with more than 1 000 000 signatures and still search through multiple megabytes of logdata per second.

[1] http://en.wikipedia.org/wiki/Commentz-Walter_algorithm


Example Usage
=========

Example 1
---------
idsgrep evil.com logdata.gz

This command wil print all lines containg the domain evil.com. Compared to normal GNU Grep, IDSGrep will not match on the domain "notevil.com"

Example 2
---------
idsgrep 192.168.2.0/24 logdata.gz

Understands the CIDR and will match on all IP-adresses in the CIDR.

Example 3
---------

evil.txt:
evil.com
159.3.2.0/24

asset.txt
192.168.0.0/16


idsgrep -b evil.txt -a asset.txt logdata.gz

Will print all lines that match any of the signatures in evil.txt. For each line that matches it will then use the signatures in assets.txt and identify a victim. In the console output the attacker will be colored red and the victim colored green.


Commandline options
=========
idsgrep --help
usage:
idsgrep [OPTIONS] PATTERN [FILE...]
idsgrep [OPTIONS] [--black-db HOST | --black-file FILE] [FILE...]

IDSGrep is a GNU Grep wrapper that understands IPv4-addresses, IPv4CIDRs,
IPv4-Ranges and Domains

positional arguments:
  files

optional arguments:
  -h, --help            show this help message and exit
  -c FILE, --conf_file FILE
                        Specify config file
  --black-db HOST       Blacklist MongoDB database
  --asset-db HOST       Assetlist MongoDB database
  -b FILE, --black-file FILE
                        Blacklist file
  -a FILE, --asset-file FILE
                        Assetlist file
  -s, --save-to-mongodb
                        Store alarms in mongoDB
  -q, --quiet
  --min-fx NUM
  --no-color
  --splunk
  --tmpdir DIR          Folder for temporary files
  --logfile FILE        Logfile
  -v [VERBOSE]
