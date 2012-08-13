#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import logging
import itertools
import UserDict
import bson
import hashlib
import binascii
import urllib2
import httplib2
import base64
import os
import re

import pymongo

import signature
import matchingengine

class BaseSignatureSet(object):
    '''
        Represents a set of signatures.
        Fetches signatures from Mongodb. Is used by idsgrep          
    '''    
    def get_sig_str(self,strsig,create=False):
        try:
            return self.get_sig(bson.binary.Binary(hashlib.sha224(strsig).digest()))
        except signature.NoSig,e:    
            if create:
                return signature.Signature.new(sig=strsig)
            else:
                raise

class SignatureSetMongoDb(BaseSignatureSet):
    def __init__(self,host,db,collection):
        self.host=host
        self.db=db
        self.collection=collection
        self.conn=pymongo.Connection(host)
        self.sigs={} #Cache of sigs accessible by signame
        self.fxsigs={} #Cache of sigs accessible by fixed string representation
   
    def get_sig(self,sig): 
        try:
            return self.sigs[sig]      
        except KeyError:  
            doc=self.conn[self.db][self.collection].find_one({"_id":sig}) #Disabled sigs are not loaded initially, therefor check db.
            if doc:
                sig=signature.Signature.new(sig=doc["sig"],sigtype=doc["type"],doc=doc)  
                self.sigs[doc["_id"]]=sig
                self.fxsigs.setdefault(doc["fixedstring"],[]).append(sig)
                return sig
            else:
                raise signature.NoSig

    def get_sigs_fx(self,fixedstring):
        try:
            return self.fxsigs[fixedstring]
        except KeyError:       
            docs=self.conn[self.db][self.collection].find({"fixedstring":fixedstring})
            if docs:
                for doc in docs:
                    sig=signature.Signature.new(sig=doc["sig"],sigtype=doc["type"],doc=doc)  
                    self.sigs[doc["_id"]]=sig
                    self.fxsigs.setdefault(fixedstring,[]).append(sig)
                return self.fxsigs[fixedstring]
            else:
                raise signature.NoSig               
                
    def get_fixedstrings(self,filter={ "active":True, "white_conflict":False,"asset_conflict":False}):
        fx=set()
        for doc in self.conn[self.db][self.collection].find(filter,["fixedstring"]):
            fx.add(doc["fixedstring"])
        return fx
        
    def get_sigs(self,filter={ "active":True, "white_conflict":False,"asset_conflict":False}):
        for doc in self.conn[self.db][self.collection].find(filter):
            sig=signature.Signature.new(sig=doc["sig"],sigtype=doc["type"],doc=doc)  
            yield sig        
   
    def get_sigs_from_source(self,source):
        return self.get_sigs({"sources." + source:{"$exists":True}})
        
    def save_sig(self,sig):
        sig.calc_score(self)
        sig["update_time"]=bson.datetime.datetime.now()
        try:
            self.conn[self.db][self.collection].save(sig.data)
            self.conn[self.db]["meta"].update({"_id":bson.binary.Binary(hashlib.sha224("config").digest())},{"lastupdate":bson.datetime.datetime.now()})
            
        except bson.errors.InvalidStringData,e:
            logging.error("Failed to save sig:" + str(sig))
            logging.error(str(e))

    def get_cache_filename(self):
        modtime=self.conn[self.db][self.collection].find_one({"_id":bson.binary.Binary(hashlib.sha224("conf").digest())},["lastupdate"])
        hash=hashlib.sha224(str(modtime) + str(self.host)).digest()
        return base64.b32encode(hash)
            
    def ensure_indexes(self):
        logging.debug("Ensuring correct indexes on %s.%s" % ( self.db,self.collection))
        self.conn[self.db][self.collection].ensure_index([("sig",pymongo.ASCENDING)])
        self.conn[self.db][self.collection].ensure_index([("score",pymongo.ASCENDING)])

    
class SignatureSetFile(BaseSignatureSet):
    def __init__(self,filepath):
        self.sigs={} 
        self.fxsigs={}      
        self.filepath=filepath
               
        with open(self.filepath) as fp:   
            self.parse_sigs(fp)
            
    def parse_sigs(self,text):
        for line in text:
            strsig=self.parse_line(line)
            if not strsig: continue
            sig=signature.Signature.new(strsig)            
            self.sigs[sig["_id"]]=sig
            self.fxsigs.setdefault(sig["fixedstring"],[]).append(sig)
    
    def parse_line(self,line):
        return re.split("[;#]",line,1)[0].strip()
        
    def get_cache_filename(self):
        modtime=str(os.path.getmtime(self.filepath))
        hash=hashlib.sha224(modtime + self.filepath).digest()
        return base64.b32encode(hash)

    def get_sig(self,sig): 
        try:
            return self.sigs[sig]      
        except KeyError:  
            raise signature.NoSig

    def get_sigs_fx(self,fixedstring):
        try:
            return self.fxsigs[fixedstring]
        except KeyError:  
            raise signature.NoSig

    def get_sigs(self):
        return self.sigs.values()

    def get_sigs_from_source(self):
        return self.sigs.values()
               
    def get_fixedstrings(self):
        sigs=set()
        for sig in self.sigs.values():
            sigs.add(sig["fixedstring"])
        return sigs        

 
class SignatureSetText(SignatureSetFile):
    def __init__(self,text):
        self.text=text
        self.sigs={} 
        self.fxsigs={}    
        self.parse_sigs(text.split("\n"))
        
    def get_cache_filename(self):
        hash=hashlib.sha224(self.text).digest()
        return base64.b32encode(hash)
 
if __name__=="__main__":
    pass
    