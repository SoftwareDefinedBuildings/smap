
import pycurl
import cStringIO as StringIO
try:
    import simplejson as json
except ImportError:
    import json

def mkrequest(c, spec):
    c.url = spec
    c.body = StringIO.StringIO()
    c.http_code = -1
    c.setopt(pycurl.URL, c.url)
    c.setopt(pycurl.WRITEFUNCTION, c.body.write)
    return c

def get(getspec, nconns=5, parser=json.load, select_timeout=1.0):
    """get a list of urls, using a connection pool of up to nconn connections.
    apply "parser" to each of the results.

    Based on retriever-multi.py.
    """
    rv = []
    m = pycurl.CurlMulti()
    m.handles = []
    for spec in xrange(nconns):
        c = pycurl.Curl()
        c.fp = None
        c.setopt(pycurl.FOLLOWLOCATION, 1)
        c.setopt(pycurl.MAXREDIRS, 5)
        c.setopt(pycurl.CONNECTTIMEOUT, 30)
        c.setopt(pycurl.TIMEOUT, 300)
        c.setopt(pycurl.NOSIGNAL, 1)
        m.handles.append(c)

    freelist = m.handles[:]
    num_processed, num_urls = 0, len(getspec)
    while num_processed < num_urls:
        while getspec and freelist:
            spec = getspec.pop(0)
            c = freelist.pop()
            mkrequest(c, spec)
            m.add_handle(c)

        while 1:
            ret, num_handles = m.perform()
            if ret != pycurl.E_CALL_MULTI_PERFORM: 
                break

        while 1:
            num_q, ok_list, err_list = m.info_read()
            for c in ok_list:
                # print "Success:", c.url, c.getinfo(pycurl.EFFECTIVE_URL)
                rv.append((c.url, c.body))
                c.fp = None
                c.body = None
                m.remove_handle(c)
                freelist.append(c) 

            for c, errno, errmsg in err_list:
                m.remove_handle(c)
                print "Failed: ", c.url, errno, errmsg
                freelist.append(c)

            num_processed += len(ok_list) + len(err_list)
            if num_q == 0:
                break

        m.select(select_timeout)

    for c in m.handles:
        c.close()
    m.close()

    map(lambda (_, x): x.seek(0), rv)
    return map(lambda (u, x): (u, parser(x)), rv)
    
