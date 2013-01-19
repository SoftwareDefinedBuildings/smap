"""Apply a stylesheet to an XML file"""

import sys
from lxml import etree

if len(sys.argv) != 3:
    print >>sys.stderr, "Usage: %s <stylesheet> <xml doc> ..." % sys.argv[0]
    sys.exit(1)

transform = etree.XSLT(etree.XML(open(sys.argv[1], "r").read()))
for xmlfile in sys.argv[2:]:
    with open(xmlfile, "r") as fp:
        doc = etree.parse(fp)
    print(etree.tostring(transform(doc), pretty_print=True))
