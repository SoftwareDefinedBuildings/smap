
import sys
import BinaryJson
import schema

if __name__ == '__main__':
    ss = BinaryJson.ListSchemaSource(schema.__schema__)
    data = sys.stdin.read(1024)
    schema = ss.getByDigest(data[0:4])
    if schema != None:
        decmpr = BinaryJson.BinaryJson(schema)
        print "read", len(data), "bytes"
        print decmpr.deserialize(data)
    else:
        print "ERROR: no matching schema found!\n"
