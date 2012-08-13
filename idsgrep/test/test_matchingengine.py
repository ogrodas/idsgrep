import unittest
import tempfile
import datetime
import subprocess

from idsgrep import signatureset
from idsgrep import matchingengine
from idsgrep import signature

class MatchingEngineTest(unittest.TestCase):

    def setUp(self):
        conn["testdb"]["black"].drop() 
        conn["testdb"]["white"].drop()      
    
    def testCDIR(self):
        sigset=signatureset.SignatureSetText("192.168.1.0/24")        
        search=matchingengine.MatchingEngine(sigset)               
        data="asdf 192.168.1.1 asdf"        
        m=search.findall(data)[0]
        self.assertEqual(m.data[m.start:m.stop],"192.168.1.1")
    
    def testDomain(self):
        sigset=signatureset.SignatureSetText("evil.com.")        
        search=matchingengine.MatchingEngine(sigset)               
        data="asdf evil.com asdf"        
        m=search.findall(data)[0]
        self.assertEqual(m.data[m.start:m.stop],"evil.com")
        
        
class FGrepMatchingEngineTest(unittest.TestCase):
    def testDomain(self):
        sigset=signatureset.SignatureSetText("evil.com.")              
        search=matchingengine.FGrepMatchingEngine(sigset)               
        data=tempfile.NamedTemporaryFile(delete=False)
        data.write("asdf evil.com asdf\n")
        data.close()
        m=search.findall_files([data.name]).next()[0] 
        self.assertEqual(m.data[m.start:m.stop],"evil.com")

    def testSTDIN(self):
        sigset=signatureset.SignatureSetText("evil.com.")              
        search=matchingengine.FGrepMatchingEngine(sigset)      
        matches=search.findall_files(stdin=subprocess.PIPE)
        search.p.stdin.write("asdf evil.com asdf\n")
        search.p.stdin.close()
        m=matches.next()[0] 
        self.assertEqual(m.data[m.start:m.stop],"evil.com")

        
if __name__ == '__main__':
    unittest.main()    