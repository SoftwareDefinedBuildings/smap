
import re
import sys
import MySQLdb

class MySQLdriver():
    """Inserting ACme readings into database"""
    def __init__(self):
        # hardcode these for now but will make them class init args later
        self.conn = MySQLdb.connect (host = "128.32.37.210",
                                user = "acme",
                                db = "acme",
                                passwd = "410soda")
        
        self.conn2 = MySQLdb.connect (host = "128.32.37.210",
                                user = "acme",
                                db = "acme2",
                                passwd = "410soda")
        
        self.cursor = self.conn.cursor();
        self.cursor2 = self.conn2.cursor();
    
    def insertDB(self,reading,debug):
        moteid,seq,power,averagePower,maxPower,minPower,energy,totalEnergy = reading
        parent,parent_metric,parent_etx,hop_limit = debug
        
        insert = "INSERT INTO energy VALUES (NOW(),"
        insert += str(moteid) + "," + str(energy) + ","
        insert += str(power) + "," + str(maxPower) + ","
        insert += str(minPower) + "," + str(averagePower) + ","
        insert += str(seq)
        insert += ");"
        
        # print insert
        try:
            self.cursor.execute(insert)
        except self.cursor.Error, e:
            print "Data duplicate detected"
            print "Error %d: %s" % (e.args[0], e.args[1])
        
        insert2 = "INSERT INTO energy VALUES ("
        insert2 += str(moteid) + "," + "NOW()," + str(seq) + ","
        insert2 += str(power) + "," + str(averagePower) + ","
        insert2 += str(maxPower) + "," + str(minPower) + ","
        insert2 += str(energy) + "," + str(totalEnergy)
        insert2 += ");"
        
        # print insert2
        try:
            self.cursor2.execute(insert2)
        except self.cursor2.Error, e:
            # print "Data duplicate detected"
            print "Error %d: %s" % (e.args[0], e.args[1])
        
        debug = "INSERT INTO debug VALUES ("
        debug += str(moteid) + "," + "NOW()," + str(seq) + ","
        debug += str(parent) + "," + str(parent_metric) + ","
        debug += str(parent_etx) + "," + str(hop_limit) + ","
        debug += "0);"
	    
        # print "This is the debug: ", debug
        try:
            self.cursor2.execute(debug)
        except self.cursor2.Error, e:
            # print "Data duplicate detected"
            print "Error %d: %s" % (e.args[0], e.args[1])
    
    def closeDB():
        conn.close()

