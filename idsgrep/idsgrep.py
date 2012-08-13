#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""IDSGrep is a GNU Grep wrapper that understands IPv4-addresses, IPv4CIDRs, IPv4-Ranges and Domains
"""

import logging
logging.basicConfig(format="%(asctime)s - %(levelname)8s - %(message)s")

import sys
import datetime
import csv
import ConfigParser

import argparse

import matchingengine
import signatureset
import alarm

USAGE=\
"""
idsgrep [OPTIONS] PATTERN [FILE...]
idsgrep [OPTIONS] [--black-db HOST | --black-file FILE] [FILE...]
"""

def main():
    try:
        args=parse_args()
        setup_logging(args)
        TibIDS(args)
    except KeyboardInterrupt,e:
        sys.stderr.write("User presdd Ctrl+C. Exiting..\n")
    except IOError as (errno, strerror):
        if errno==32 and strerror=="Broken pipe":
            sys.stderr.write("Broken pipe. Exiting..\n")
        else:
            logging.exception(strerror)
    except Exception,e:
        logging.exception(str(e))

        
def parse_args(argv=None):
    if argv is None:
        argv = sys.argv

    # Parse any conf_file specification
    # We make this parser with add_help=False so that
    # it doesn't parse -h and print help.
    conf_parser = argparse.ArgumentParser(
        # Don't mess with format of description
        formatter_class=argparse.RawDescriptionHelpFormatter,
        # Turn off help, so we print all options in response to -h
        add_help=False
        )
    conf_parser.add_argument("-c", "--conf_file",
                        help="Specify config file", metavar="FILE")
    args, remaining_argv = conf_parser.parse_known_args()

    if args.conf_file:
        config = ConfigParser.SafeConfigParser()
        config.read([args.conf_file])
        print args.conf_file
        defaults = dict(config.items("Defaults"))
    else:
        defaults = { }

    # Parse rest of arguments
    # Don't suppress add_help here so it will handle -h
    parser = argparse.ArgumentParser(
        # Inherit options from config_parser
        description=__doc__, # printed with -h/--help
        usage=USAGE,
        parents=[conf_parser]
        )
    parser.set_defaults(**defaults)
    
    parser.add_argument ('--black-db',metavar="HOST", default=None,help='Blacklist MongoDB database')
    parser.add_argument ('--asset-db',metavar="HOST",default=None,help='Assetlist MongoDB database')
    parser.add_argument ('-b','--black-file',metavar="FILE",default="",help='Blacklist file')
    parser.add_argument ('-a','--asset-file',metavar="FILE",default="",help='Assetlist file')  
    parser.add_argument ('-s','--save-to-mongodb',default=False, action="store_true", help='Store alarms in mongoDB') 
    parser.add_argument ('-q','--quiet',default=False, action="store_true", help='') 
    parser.add_argument ('--min-fx',metavar="NUM",default=5, help='') 
    parser.add_argument ('--no-color',default=False, action="store_true", help='') 
    parser.add_argument ('--splunk',default=False, action="store_true", help='') 
    parser.add_argument ('--tmpdir',metavar="DIR",default="/tmp/", help='Folder for temporary files') 
    parser.add_argument ('--logfile',metavar="FILE",default="", help='Logfile')
    parser.add_argument('-v', nargs='?', action=VAction, dest='verbose',default=2)
    parser.add_argument ('files', nargs="*",default=None, help='')   
    return parser.parse_args(remaining_argv)
        
def setup_logging(args):    
    log_mapping={
        0:50, #Disable logging
        1:logging.ERROR,
        2:logging.WARNING,
        3:logging.INFO,
        4:logging.DEBUG
    }    
    
    logging.root.setLevel(log_mapping[args.verbose])
    try:
        if args.logfile:
            fh = logging.FileHandler(args.logfile)
            fh.setLevel(logging.DEBUG)
            fh_formatter = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
            fh.setFormatter(console_formatter)
            logging.getLogger('').addHandler(fh)
    except IOError,e:
        logging.warning("Can't write log to logfile %s", args.logfile)
        pass #No logging to file
        
class VAction(argparse.Action):
    def __call__(self, parser, args, values, option_string=None):
        if values==None:
            values='1'
        try:
            values=int(values)
        except ValueError:
            values=values.count('v')+1
        setattr(args, self.dest, values)
        
class TibIDS(object):
    def __init__(self,args):
        self.args=args
        
        if args.black_file:        
            self.black=signatureset.SignatureSetFile(self.args.black_file)
        elif args.black_db:
            self.black=signatureset.SignatureSetMongoDb(self.args.black_db,"sigdb","black")
        else:
            if args.files:
                strsig=self.args.files.pop(0)
                self.black=signatureset.SignatureSetText(strsig)
            else:
                print "Missing signatures."
                print "Try `idsgrep --help' for more information."
                sys.exit(1)
                  
        if self.args.asset_file:
            self.asset=signatureset.SignatureSetFile(self.args.asset_file)
        elif self.args.asset_db:
            self.asset=signatureset.SignatureSetMongoDb(self.args.asset_db,"sigdb","asset")
        else:
            self.asset=None
  
        self.black_search=matchingengine.FGrepMatchingEngine(self.black,min_fx=int(self.args.min_fx))        
        if self.asset:
            self.asset_search=matchingengine.MatchingEngine(self.asset)
                
        if self.args.splunk:
            self.start_splunk()
        else:
            self.start()
    
    def search(self):
        for matches in self.black_search.findall_files(self.args.files):
            victim=self.find_victim(matches[0].data)
            yield alarm.Alarm(matches,victim)
            
    def find_victim(self,data):
        #TODO find the most important victim, not the first
        if not self.asset:
            return None
        victims=self.asset_search.findall(data)
        for v in victims:
            return v.data[v.start:v.stop]      
            
    def start_splunk(self):       
        fieldnames=csv.DictReader(sys.stdin).fieldnames
        fieldnames.append("sig")
        fieldnames.append("score")
        fieldnames.append("victim")
        print ",".join(fieldnames)
        for alarm in self.search():
            for match in alarm.matches:                
                print alarm.data + "," + ",".join([match.sig["sig"],str(match.sig["score"]),alarm.victim])                           
      
    def start(self):
        for alarm in self.search():           
            if not self.args.quiet:
                if self.args.no_color:
                    print alarm.data
                else:
                    print alarm.colors()
            if self.args.save_to_mongodb:
                alarm.save("alarms","alarms")                               
                
     
if __name__=="__main__":
    main()
