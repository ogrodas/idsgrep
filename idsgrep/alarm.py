import re
import bson
import hashlib
import binascii
import datetime
import sys
import logging
import bson

from colorama import Fore

import argparse
import pymongo
import signatureset

                        
conn=pymongo.Connection()
                        
                        
class Alarm():
    def __init__(self,matches,victim,time=None):
        self.matches=matches
        self.victim=victim
        self.data=matches[0].data.strip()
        self.time=self.find_timestamp()
        
    def __repr__(self):
          return self.data
                  
    def find_timestamp(self):
        try:# Unix timestamp, Example 1335823199
            return datetime.datetime.utcfromtimestamp(float(self.data[:10]))
        except (ValueError,TypeError),e:
            pass
        
        try:# Standard time format, Example 2012-04-01 09:47:01
            return datetime.datetime.strptime(self.data[:19],"%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass   
        
        logging.debug("Can't interpret log timestamp, using now()")
        return datetime.datetime.now()
        
    def get_matches(self):
        return [m.data[m.start:m.stop] for m in self.matches]
        
    def colors(self,color=True):
        if not color:
            return self.data
        else:                
            regexp= '(' + '|'.join(self.get_matches()) + ')'
            data=re.sub(regexp, Fore.RED + r'\1' + Fore.RESET, self.data)              
            data=re.sub('(%s)' % self.victim, Fore.GREEN + r'\1' + Fore.RESET, data)
            #data=re.sub('(%s)' % attacker, Fore.RED + r'\1' + Fore.RESET, data)             
            return data    

    def save(self,db,collection):
        #Save current alarm
        conn[db][collection].save({
            "_id":bson.Binary(hashlib.sha224(self.data).digest()),
            "time":self.time,
            "victim":self.victim,
            "sigs":[m.sig["_id"] for m in self.matches],
            "score":pow(sum(m.sig["score"]**2 for m in self.matches),0.5),
            "data":self.data,
        })
    
    

class AlarmDb(object):
    def __init__(self,db):
        self.db=db
        self.sigset=signatureset.BlackSignatureSet()
        self.aggs=[AlarmAggHour(db,self.sigset),AlarmAggDay(db,self.sigset)]
    
    def update_aggs(self,last_update):
        '''
            Read all alarms since last time the function was runned.
                1. increment aggregates.
                2. Recalculate the score for all aggregates from that has been changed. 
        '''
        if not last_update:
            last_update = conn[self.db]["meta"].find_one( {"last_agg_update":{"$exists":True}})
            if not last_update:
                last_update=datetime.datetime.min
            else:
                last_update=last_update["last_agg_update"]
        now = datetime.datetime.now()
                       
        logging.debug("Updating aggregate collections")
        cursor= conn[self.db]["alarms"].find({"time": {"$gte":last_update}})        
        for doc in cursor:
            for agg in self.aggs:
                agg.update(doc)
        
        logging.debug("Recalculating aggregate score")
        for agg in self.aggs:
            agg.recalc_score(last_update)

        conn[self.db]["meta"].save({"last_agg_update":now})
 
class AlarmAgg(object):       
    def update(self,doc):
        conn[self.db][self.collection].update(
            {            
                "timebucket": self.bucket(doc["time"]), 
                "victim":doc["victim"]
            },
            { "$inc": dict( ("sigs." + binascii.hexlify(id),1) for id in doc["sigs"])},
            True,
        )  
    
    
    def recalc_score(self,start):
        last_update=self.bucket(start)
        cursor= conn[self.db][self.collection].find({"timebucket": {"$gte":last_update}})        
        for doc in cursor:
            self.recalc_score_doc(doc)
    

    def recalc_score_doc(self,doc):
        scores=[]
        for sig,count in doc["sigs"].items():
            sig=self.sigset.get_sig(bson.Binary(binascii.unhexlify(sig)))
            scores.append(sig["score"]*4/(1+3/count))    
        score=pow(sum(score**2 for score in scores),0.5)
        doc["score"]=score
        conn[self.db][self.collection].save(doc)


class AlarmAggHour(AlarmAgg):
    def __init__(self,db,sigset):
        self.db=db
        self.collection="alarms_agg_hour"
        self.sigset=sigset
        
    def bucket(self,timestamp):
        return timestamp.replace(minute=0, second=0, microsecond=0)

class AlarmAggDay(AlarmAgg):
    def __init__(self,db,sigset):
        self.db=db
        self.collection="alarms_agg_day"
        self.sigset=sigset
    
    def bucket(self,timestamp):
        return timestamp.replace(hour=0,minute=0, second=0, microsecond=0)


def parse_options(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument ('--all',default=False, action="store_true", help='Update all allarms')         
    return parser.parse_args(argv)

def main():
    args=parse_options()
    a=AlarmDb("alarms")
    lastupdate=None
    if args.all:
        lastupdate=datetime.datetime.min
    a.update_aggs(lastupdate)
          
if __name__=="__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt,e:
        sys.stderr.write("User presdd Ctrl+C. Exiting..\n")
    except IOError as (errno, strerror):
        if errno==32 and strerror=="Broken pipe":
            sys.stderr.write("Broken pipe. Exiting..\n")    


            