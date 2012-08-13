#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import logging
import sys
import gzip
import tempfile
import shlex
import subprocess
import re
import atexit
import os
import signal
import shutil

import ahocorasick

import signature

logging.basicConfig(level=logging.DEBUG)

MIN_FIXED_STRING_LENGHT=3

class MatchingEngine(object):
    def __init__(self,sigs,min_fx=MIN_FIXED_STRING_LENGHT):
        self.sigs=sigs
        start_time=datetime.datetime.now()
        self.tree = ahocorasick.KeywordTree()        
        for fixedstring_sig in sigs.get_fixedstrings():
            if fixedstring_sig>min_fx:
                self.tree.add(fixedstring_sig)
            else:
                logging.warning("Ignoring signature %s because fixed string representation is less than % i " % (fixedstring_sig,min_fx))
           
        self.tree.make()
        end_time=datetime.datetime.now()
        logging.debug("Signature download and index build time" + str(end_time - start_time))
        
    def findall(self,string):
        matches=[]
        for start,stop in self.tree.findall(string):
            match=string[start:stop]
            for sig in self.sigs.get_sigs_fx(match):
                try:
                    match=sig.verify_match(start,stop,string)
                    matches.append(match)
                    continue # TODO: If multiple signature different signature has the exact same match this might lead to problems.
                except signature.NoMatch:
                    pass
                    #TODO: add handling for over matching. If a single sig is overmatching to much it should be disabled or tuned 
        return matches
      

    def findall_file (self,file=None):
        def _linereader(file):
            if not file:
                for line in sys.stdin:
                    yield line
            else:
                if file.endswith(".gz"):
                    f=gzip.GzipFile(file)
                else:
                    f=open(file)                
                for line in f:
                    yield line
        
        for line in _linereader(file):
            matches=self.findall(line)
            if matches:
                yield matches
           

class FGrepMatchingEngine(object):
    def __init__(self,sigs,min_fx=MIN_FIXED_STRING_LENGHT,tmpdir="/tmp/"):   
        self.tmpdir=tmpdir
        self.sigs=sigs
        start_time=datetime.datetime.now()                        
        self.sigfile=os.path.join(self.tmpdir,sigs.get_cache_filename())
        if not os.path.exists(self.sigfile):        
            logging.debug("No up-to-date fixedstring cache availabe, creating fixedstring signature set...")
            with open(self.sigfile + ".update","w+") as f:
                for fixedstring_sig in sigs.get_fixedstrings():  
                    if fixedstring_sig>min_fx:
                         f.write(fixedstring_sig + "\n")
                    else:
                        logging.warning("Ignoring signature %s because fixed string representation is less than % i " % (fixedstring_sig,min_fx))
                index_build_time=datetime.datetime.now()            
            shutil.move(self.sigfile + ".update", self.sigfile)
        else:
            logging.debug("Using %s for fixedstring cache" % self.sigfile)
        end_time=datetime.datetime.now()
        logging.debug("Signature download and index build time" + str(end_time - start_time))
        
    def _read_results(self,p):
        sig_re=re.compile("\x1b\[01;31m\x1b\[K(.*?)\x1b\[m\x1b\[K") # Grep output uses color matches, this will extract matches
        for line in p.stdout:
            noncolor="" #The line that has the match stripped, strippe 
            grep_matches=[]
            offset=0
            for m in sig_re.finditer(line):
                match=m.groups()[0]
                noncolor+=line[offset:m.start()]
                grep_matches.append((match,len(noncolor),len(noncolor)+len(match)))
                noncolor+=match
                offset=m.end()
            noncolor+=line[offset:]

            matches=[]
            for match,start,stop in grep_matches:            
                for sig in self.sigs.get_sigs_fx(match):
                    try:
                        match=sig.verify_match(start,stop,noncolor)
                        matches.append(match)
                        continue # TODO: If multiple signature different signature has the exact same match this might lead to problems.
                    except signature.NoMatch:
                        pass
                        #TODO: add handling for over matching. If a single sig is overmatching to much it should be disabled or tuned 
                
            if matches:
                yield matches
        
    def findall_files (self,files="",stdin=None):
        """
            Supply a list of filenames to zgrep.
            If files=None grep will read from stdin.
            If stdin=None no redirection will occur; the grep file handles will be inherited from the parent
            if stdin=subprocess.PIPE self.p.stdin can be used to write data to grep.
            
            The cleanup and get_child_processes are needed to make sure that zgrep,gzip,grep etc are really killed.
        """
        def cleanup():             
            pids=get_child_processes(self.p.pid)
            for pid in pids:
                os.kill(pid,signal.SIGKILL)
            
        def get_child_processes(parent_pid):
                ps_command = subprocess.Popen("ps -o pid --ppid %d --noheaders" % parent_pid, shell=True, stdout=subprocess.PIPE)
                ps_output = ps_command.stdout.read()
                children=[]
                children.append(parent_pid)
                for line in ps_output.split("\n"):
                    if line:
                        child=int(line)
                        children.extend(get_child_processes(child))                
                return children
        
        
        #Search logfiles write alarms to tempfile
        cmd="zgrep -h --color=always -F -f %s %s" % (self.sigfile," ".join(files))
        args=shlex.split(cmd)
        self.p = subprocess.Popen(args,stdout=subprocess.PIPE,stdin=stdin)        
        atexit.register(cleanup)
        return self._read_results(self.p)

        
if __name__=="__main__":
    pass
    