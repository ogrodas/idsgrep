import unittest

from idsgrep.signature import *

class SignatureNewTest(unittest.TestCase):
    def test_IP(self):
        sig=Signature.new("192.168.2.1")
        self.assertTrue(isinstance(sig,IP), "new not classifying correctly")
        self.assertEqual(sig["fixedstring"],"192.168.2.1","fixed string error")

    def test_CIDR(self):
        sig=Signature.new("192.168.2.0/24")
        self.assertTrue(isinstance(sig,CIDR), "new not classifying CIDR correctly")
        self.assertEqual(sig["fixedstring"],"192.168.2.","CIDR fixed string error")
      
    def test_IPRange(self):
        sig=Signature.new("192.168.1.0-192.168.1.254")
        self.assertTrue(isinstance(sig,IPRange), "new not classifying correctly")
        self.assertEqual(sig["fixedstring"],"192.168.1.","fixed string error")

    def test_Domain(self):
        sig=Signature.new("evil.com")
        self.assertTrue(isinstance(sig,Domain), "new not classifying correctly")
        self.assertEqual(sig["fixedstring"],"evil.com","fixed string error")

    def test_FixedString(self):
        sig=Signature.new("asdfasdf.asdf")
        self.assertTrue(isinstance(sig,FixedString), "new not classifying correctly")
        self.assertEqual(sig["fixedstring"],"asdfasdf.asdf","fixed string error")
              
    def test_verifymatch_IP1(self):         
        data="192.168.2.11"
        strsig="192.168.2.1"  
        sig=Signature.new(strsig)  
        self.assertRaises(NoMatch,sig.verify_match,0,len(strsig),data)
    
    def test_verifymatch_IP2(self):
        data="192.168.2.1asdf "
        strsig="192.168.2.1"
        sig=Signature.new(strsig)  
        m=MatchObject(0,len(strsig),data,sig)
        self.assertEqual(m,sig.verify_match(0,len(strsig),data))
                
    def test_verifymatch_Domain(self):
        data="evil.com"
        strsig="il.co"
        sig=Signature.new(strsig)  
        self.assertRaises(NoMatch,sig.verify_match,0,len(strsig),data)

    def test_verifymatch_Domain2(self):
        data="#evil.com#"
        strsig="evil.com"
        sig=Signature.new(strsig)  
        m=MatchObject(1,len(strsig)+1,data,sig)
        self.assertEqual(m,sig.verify_match(1,len(strsig)+1,data))
 
    def test_verifymatch_CIDR1(self):
        data="192.168.0.199"
        strsig="192.168.0.0/25"
        sig=Signature.new(strsig)  
        m=MatchObject(0,len(data),data,sig)
        self.assertRaises(NoMatch,sig.verify_match,0,len(data),data)
 
    def test_verifymatch_CIDR2(self):
        data="192.168.2.150"
        strsig="192.168.2.0/24"
        sig=Signature.new(strsig)  
        m=MatchObject(0,len(data),data,sig)
        self.assertEqual(m,sig.verify_match(0,len(strsig),data))       
        
    def test_verifymatch_CIDR2(self):
        data="212.58.246.92"
        strsig="12.58.246.0/24"
        sig=Signature.new(strsig)  
        self.assertRaises(NoMatch,sig.verify_match,0,len(strsig),data)
      
        

        

if __name__ == '__main__':
    unittest.main()
