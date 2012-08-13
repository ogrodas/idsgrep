#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import netaddr
import itertools
import string
import collections
import UserDict
import sys
import bson
import hashlib
import logging

class NoMatch(Exception):pass
class NoSig(Exception):pass

"""   
    The Signature class is design to make it possible to express standard IDS signatures in way that makes it
    possible to efficiently search logdata with a very large set signatures. 
    
    The requirement is that a simplified version of the signature can be expressed as a fixed string.
    The fixed string representation must have zero false negativs but can have many false positves.
    
    The Matching engine loads loads the fixed string represation scans the logdata in one pass with
    all signatures. When a fixed string is matches the signatures verify_match method is called
    to make sure that it is not a FP from the simplified fixed string representation. The fixed string 
    represenation can be considered a guard for the more resource intensive full singature that
    is expressed in verify_match.
   
    Signature inherihts from Userdict. All attributes of the signature is stored as a dict in self.doc. 
    Saving and loading the signature to permanent storage is therefor done by saving and loading the self.doc
    dict. This design is choosen to make it more easy to store the signatures in a docuemnt store.
    Currently MongoDB is used.
    
    Signature has two class methods new and classify. classify is designed to be able to detect the correct
    signature subclass based on the string representation of the signature. For example a IP-adresse
    "192.168.1.1" is detected as an IP-adress and an instance of IP signature sub class is created
 
    Structure of self.data:
    {
        "_id":sha224(sig)
        "sig":[string]
        "type"[IP/CIDR/IPRange/Domain/Fixedstring]
        "fixedstring":[string]
        
        "tuned":[Boolean],
        "active":[Boolean],
        "white_conflict":[Boolean],
        "asset_conflict":[Boolean],
        
        "enable_time":[timestamp],
        "update_time":[timestamp],
        "disable_time":[timestamp],
        
        "sources" {
            [src1]: {
                "tags":[[tag1],[tag2]...]
                "score":[0-100]
                "comment":[string]               
            }, 
            [src2]: {
                "tags":[[tag1],[tag2]...]
                "score":[0-100]
                "comment":[string]               
            },
            ...            
        }
        "score":[int]
    }      
"""


class Signature (UserDict.UserDict):
    def __init__(self,sig,type,doc=None):
        if not doc:           
            doc = {
                "_id":bson.binary.Binary(hashlib.sha224(sig).digest()),
                "sig":sig,
                "type":type,
                "fixedstring":None,                
                "tuned":False,
                "active":True,
                "white_conflict":False,
                "asset_conflict":False,
                "enable_time": bson.datetime.datetime.now(),
                "update_time": bson.datetime.datetime.now(),
                "disable_time":bson.datetime.datetime(year=9999,month=12,day=31),
                "sources": {},
            }
        UserDict.UserDict.__init__(self,doc)
       
    def verify_match(self,start,stop,data):
        return MatchObject(start,stop,data,self)        
        
    def __repr__(self):
        return '%s ( %s )' % (self["type"],self["sig"])
          
    def calc_score(self,sigset):
        scores=[]
        for src,srcdata in self["sources"].items():           
            scores.append(srcdata["score"])
        score=pow(sum(pow(s,2) for s in scores),0.5)        
        self["score"]=score


    classify_re=None
    @classmethod
    def classify(cls,sig):
        if not Signature.classify_re: #Compile regex on first use       
            classes=[
                        IPRange.RANGE_str,
                        CIDR.CIDR_str,
                        IP.IP_str,
                        Domain.domain
                    ]
            Signature.classify_re=re.compile("|".join("(^%s$)" % el for el in classes),re.IGNORECASE)
        match=Signature.classify_re.match(sig)

        if not match:
            return "FixedString"
        else:
            #Find the group that matched
            return list(key for key,value in match.groupdict().items() if value and key not in ["start","stop"])[0]

    
    @classmethod
    def new (cls,sig,sigtype=None,doc=None):
        """Create an instance of the correct subclass of Signature."""
        if not sigtype: 
            if doc:
                sigtype=doc["type"]
            if not sigtype:    
                sigtype=Signature.classify(sig)            
        if sigtype=="IP":
            return IP(sig,sigtype,doc)
        elif sigtype=="CIDR":
            return CIDR(sig,sigtype,doc)
        elif sigtype=="IPRange":
            return IPRange(sig,sigtype,doc)
        elif sigtype=="Domain":
            return Domain(sig,sigtype,doc)
        elif sigtype=="FixedString": 
            return FixedString(sig,sigtype,doc)
        else:  
            raise Exception ("Signature: %s, type: %s" % (sig,sigtype))

            
class FixedString(Signature):
    def __init__(self,sig,type="FixedString",doc=None):
        Signature.__init__(self,sig,type,doc)
        self["fixedstring"]=sig
       
        
class IP(Signature):
    IP_str="(?P<IP>(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))"
    IP_exact="^%s$" % IP_str
    exact_re=re.compile(IP_str)   
    
    def __init__(self,sig,type="IP",doc=None):
        Signature.__init__(self,sig,type,doc)
        if not doc:
            self["fixedstring"]=sig
            ip=netaddr.IPAddress(sig)
            self["start"]=ip.value
            self["stop"]=ip.value
        
    @property
    def start(self): return self["start"]
    
    @property
    def stop(self): return self["stop"]
    
    def verify_match(self,start,stop,data):
        '''Checks for over matching. For example 192.168.1.1 matching on 192.168.1.11'''
        if start-1>0:
            if data[start-1] in string.digits :
                raise NoMatch
        if stop<len(data):
            if data[stop] in string.digits:
                raise NoMatch
        return MatchObject(start,stop,data,self)

        
class IPRangeBase(Signature):
    def __init__(self,sig,type="CIDR",doc=None):
        Signature.__init__(self,sig,type,doc)


    @property
    def start(self): return self["start"]
    
    @property
    def stop(self): return self["stop"]
     
    def verify_match(self,start,stop,data):
        '''
            Checks that the match is a valid IP-adress
        '''
        
        #Checks for over matching. For example that 192.168.1.1 is not matching on 192.168.1.11'
        if start-1>0:
            if data[start-1] in string.digits :
                raise NoMatch
        
        m=IP.exact_re.match(data[start:])
        
        if m:
            addr=netaddr.IPAddress(data[start:start+m.end()])
            if addr.value>= self["start"] and addr.value<=self["stop"]:
                return MatchObject(start,start+m.end(),data,self)
        raise NoMatch
        
    def get_fixedstring(self):
        #return the string prefix of the IP-range
        start=str(netaddr.IPAddress(self["start"]))
        stop=str(netaddr.IPAddress(self["stop"]))
        common=[]
        for a,b in zip(start,stop):
            if a!=b: 
                break
            common.append(a)
        return "".join(common)        

        
class CIDR(IPRangeBase):
    CIDR_str="(?P<CIDR>(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:(3[0-2])|[1-2][0-9]|[0-9]))"
    CIDR_exact="^%s$" % CIDR_str
    exact_re=re.compile(CIDR_exact)
    
    def __init__(self,sig,type="CIDR",doc=None):
        IPRangeBase.__init__(self,sig,type,doc)

        if not doc:        
            net=netaddr.IPNetwork(sig)
            self["start"]=net.first
            self["stop"]=net.last        
            self["fixedstring"]=self.get_fixedstring()

      
class IPRangeParseError(Exception):pass        
class IPRange(IPRangeBase):
    RANGE_str="(?P<IPRange>(?P<start>(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)) ?- ?(?P<stop>(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))"
    RANGE_exact="^%s$" % RANGE_str
    exact_re=re.compile(RANGE_exact)
    
    def __init__(self,sig,type="IPRange",doc=None):
        IPRangeBase.__init__(self,sig,type,doc)
        if not doc:
            m=IPRange.exact_re.match(sig)
            try:
                start=m.groupdict()["start"]
                stop=m.groupdict()["stop"]  
                self.net=netaddr.IPRange(start,stop)           
            except AttributeError,e:
                raise IPRangeParseError(e)
            self["start"]=self.net.first
            self["stop"]=self.net.last
            self["fixedstring"]=self.get_fixedstring()

 
class Domain(Signature):
    domain=r"(?P<Domain>(?:(?:[a-z0-9]+|(?:[a-z0-9]+[a-z0-9-_]+[a-z0-9-_]+))[.])+(?:AC|AD|AE|AERO|AF|AG|AI|AL|AM|AN|AO|AQ|AR|ARPA|AS|ASIA|AT|AU|AW|AX|AZ|BA|BB|BD|BE|BF|BG|BH|BI|BIZ|BJ|BM|BN|BO|BR|BS|BT|BV|BW|BY|BZ|CA|CAT|CC|CD|CF|CG|CH|CI|CK|CL|CM|CN|CO|COM|COOP|CR|CU|CV|CX|CY|CZ|DE|DJ|DK|DM|DO|DZ|EC|EDU|EE|EG|ER|ES|ET|EU|FI|FJ|FK|FM|FO|FR|GA|GB|GD|GE|GF|GG|GH|GI|GL|GM|GN|GOV|GP|GQ|GR|GS|GT|GU|GW|GY|HK|HM|HN|HR|HT|HU|ID|IE|IL|IM|IN|INFO|INT|IO|IQ|IR|IS|IT|JE|JM|JO|JOBS|JP|KE|KG|KH|KI|KM|KN|KP|KR|KW|KY|KZ|LA|LB|LC|LI|LK|LR|LS|LT|LU|LV|LY|MA|MC|MD|ME|MG|MH|MIL|MK|ML|MM|MN|MO|MOBI|MP|MQ|MR|MS|MT|MU|MUSEUM|MV|MW|MX|MY|MZ|NA|NAME|NC|NE|NET|NF|NG|NI|NL|NO|NP|NR|NU|NZ|OM|ORG|PA|PE|PF|PG|PH|PK|PL|PM|PN|PR|PRO|PS|PT|PW|PY|QA|RE|RO|RS|RU|RW|SA|SB|SC|SD|SE|SG|SH|SI|SJ|SK|SL|SM|SN|SO|SR|ST|SU|SV|SY|SZ|TC|TD|TEL|TF|TG|TH|TJ|TK|TL|TM|TN|TO|TP|TR|TRAVEL|TT|TV|TW|TZ|UA|UG|UK|US|UY|UZ|VA|VC|VE|VG|VI|VN|VU|WF|WS|XN--0ZWM56D|XN--11B5BS3A9AJ6G|XN--3E0B707E|XN--45BRJ9C|XN--80AKHBYKNJ4F|XN--90A3AC|XN--9T4B11YI5A|XN--CLCHC0EA0B2G2A9GCD|XN--DEBA0AD|XN--FIQS8S|XN--FIQZ9S|XN--FPCRJ9C3D|XN--FZC2C9E2C|XN--G6W251D|XN--GECRJ9C|XN--H2BRJ9C|XN--HGBK6AJ7F53BBA|XN--HLCJ6AYA9ESC7A|XN--J6W193G|XN--JXALPDLP|XN--KGBECHTV|XN--KPRW13D|XN--KPRY57D|XN--LGBBAT1AD8J|XN--MGBAAM7A8H|XN--MGBAYH7GPA|XN--MGBBH1A71E|XN--MGBC0A9AZCG|XN--MGBERP4A5D4AR|XN--O3CW4H|XN--OGBPF8FL|XN--P1AI|XN--PGBS0DH|XN--S9BRJ9C|XN--WGBH1C|XN--WGBL6A|XN--XKC2AL3HYE2A|XN--XKC2DL3A5EE0H|XN--YFRO4I67O|XN--YGBI2AMMX|XN--ZCKZAH|XXX|YE|YT|ZA|ZM|ZW))\.?"
    domain_exact="^%s$" % domain
    exact_re=re.compile(domain_exact,re.IGNORECASE)
        
    def __init__(self,sig,type="Domain",doc=None):
        sig=sig.strip()
        if sig:
            if sig.endswith("."):
                sig=sig[:-1]
            
        Signature.__init__(self,sig,type,doc)
        if not doc:       
            self["fixedstring"]=sig
   
    def verify_match(self,start,stop,data):
        '''Checks for over matching. For example that evil.com is not matching on notevil.com'''
        if start-1>0:
            if data[start-1] in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789":
                raise NoMatch
        if stop<len(data):
            if data[stop] in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789":
                raise NoMatch
        return MatchObject(start,stop,data,self)

    
class MatchObject:
    def __init__(self,start,stop,data,sig):
        self.start=start
        self.stop=stop
        self.data=data
        self.sig=sig
        
    def match(self):
        return self.data[self.start:self.stop]
        
    def __repr__(self):
        return self.data[self.start:self.stop]
    
    def __eq__(self, other): 
        return self.__dict__ == other.__dict__ 

        
if __name__=="__main__":
    print Signature.new("192.168.1.1")
    print Signature.new("192.168.1.1/24")
    print Signature.new("192.168.1.0-192.168.1.254")
    print Signature.new("evil.com")
    a = Signature.new("asdfasdf")
    print a
    print isinstance(a,FixedString)
     
    