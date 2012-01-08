
import operator
import time

import querygen as qg
from data import escape_string
from querydata import extract_data
import data
from smap.util import build_recursive

import ply
import ply.lex as lex
import ply.yacc as yacc
import copy

tokens = (
    'HAS', 'AND', 'OR', 'NOT', 'LIKE', 'DISTINCT', 'STAR',
    'LPAREN', 'RPAREN', 'COMMA', 'TAGS', 'SELECT', 'WHERE',
    'QSTRING', 'EQ', 'NUMBER', 'LVALUE', 'IN', 'DATA', 'DELETE',
    'SET', 'TILDE', 'BEFORE', 'AFTER', 'NOW', 'LIMIT', 'STREAMLIMIT',
    )

reserved = {
    'where' : 'WHERE',
    'distinct' : 'DISTINCT',
    'select' : 'SELECT',
    'delete' : 'DELETE',
    'set' : 'SET',
    'tags' : 'TAGS',
    'has' : 'HAS',
    'and' : 'AND',
    'or' : 'OR',
    'not' : 'NOT',
    'like' : 'LIKE',
    'data': 'DATA',
    'in' : 'IN',
    'before' : 'BEFORE',
    'after' : 'AFTER',
    'now' : 'NOW',
    'limit' : 'LIMIT',
    'streamlimit' : 'STREAMLIMIT',
    '~' : 'TILDE',
    }

t_LPAREN = r'\('
t_RPAREN = r'\)'
t_STAR = r'\*'
t_COMMA = r','
def t_QSTRING(t):
    r'("[^"\\]*?(\\.[^"\\]*?)*?")|(\'[^\'\\]*?(\\.[^\'\\]*?)*?\')'    
    if t.value[0] == '"':
        t.value = t.value[1:-1].replace('\\"', '"')
    elif t.value[0] == "'":
        t.value = t.value[1:-1].replace("\\'", "'")
    return t

t_EQ = r'='

def t_LVALUE(t):
    r'[a-zA-Z\~][a-zA-Z0-9\/\%_\-]*'
    t.type = reserved.get(t.value, 'LVALUE')
    return t


def t_NUMBER(t):
    r'[0-9]+'
    try:
        t.value = int(t.value)
    except ValueError:
        print "Integer value too large %d", t.value
        t.value = 0
    return t

t_ignore = " \t"
def t_newline(t):
    r'[\n\r]+'
    t.lexer.lineno += t.value.count("\n")

def t_error(t):
    print("Illegal character '%s'" % t.value[0])
    t.lexer.skip(1)

smapql_lex = lex.lex()

# precedence = ('and')
names = {}

def ext_default(x):
    return map(operator.itemgetter(0), x)

def ext_deletor(x):
    data.del_streams(map(operator.itemgetter(0), x))
    return map(operator.itemgetter(1), x)

def ext_plural(x):
    rv = {}
    for uuid, tagname, tagval in x:
        if not uuid in rv:
            rv[uuid] = {'uuid' : uuid}
        rv[uuid][tagname] = tagval
    return map(lambda x: build_recursive(x, suppress=[]), rv.itervalues())

def make_select_rv(t, sqlsel, wherestmt=None):
    if wherestmt != None:
        return sqlsel[2], ("""SELECT %s FROM metadata2 m, stream s 
              WHERE stream_id IN (%s) AND %s AND
                   s.id = m.stream_id""" % \
                               (sqlsel[0], qg.normalize(wherestmt).render(), 
                                sqlsel[1]))
    else:
        return sqlsel[2], ("""SELECT %s FROM metadata2 m, stream s, subscription sub 
              WHERE s.id = m.stream_id AND s.subscription_id = sub.id
                 AND %s AND %s""" % 
                           (sqlsel[0], sqlsel[1], 
                            qg.build_authcheck(t.parser.request)))

def p_query(t):
    '''query : SELECT selector WHERE statement
             | SELECT selector
             | SELECT data_clause WHERE statement
             | DELETE tag_list WHERE statement
             | DELETE WHERE statement
             | SET set_list WHERE statement
             '''
    if t[1] == 'select':
        if len(t) == 5:
            t[0] = make_select_rv(t, t[2], t[4])
        elif len(t) == 3:
            t[0] = make_select_rv(t, t[2])
        
    elif t[1] == 'delete':
        # a new delete inner statement enforces that we only delete
        # things which we have the key for.
        delete_inner = """
   (SELECT s.id FROM stream s, subscription sub WHERE s.id IN %s
          AND s.subscription_id = sub.id AND %s)
    """ % (qg.normalize(t[len(t) - 1]).render(), 
           qg.build_authcheck(t.parser.request, forceprivate=True))
        if t[2] == 'where':
            # delete the whole stream, gone.  this also deletes the
            # data in the backend readingdb.
            t[0] = ext_deletor, \
                """DELETE FROM stream s WHERE id IN %s
                   RETURNING s.id, s.uuid
                """ % delete_inner
        else:
            # this alters the tags but doesn't touch the data
            t[0] = None, \
                ("""DELETE FROM metadata2 WHERE stream_id IN %s
                    AND (%s)""" % (delete_inner, 
                                   ' OR '.join(map(lambda x: "tagname = %s" % 
                                                   escape_string(x), 
                                                   t[2]))))
    elif t[1] == 'set':
        #  set tags by calling the add_tag stored procedure with each
        #  new tag; this'll insert or update the database as
        #  appropriate
        tag_stmt = ','.join(map(lambda (t, v): \
                                    "add_tag(m.stream_id, %s, %s)" % 
                                (escape_string(t), 
                                 escape_string(v)), 
                                t[2]))
        # filter by the selector; adding an authcheck which only lets
        # you operate on *your* streams.
        t[0] = None, \
            """SELECT %s FROM stream s, metadata2 m, subscription sub
               WHERE stream_id IN %s AND %s AND
                 s.id = m.stream_id AND s.subscription_id = sub.id
            """ % \
            (tag_stmt,
             qg.normalize(t[4]).render(),
             qg.build_authcheck(t.parser.request, forceprivate=True))

def p_selector(t):
    '''selector : tag_list
                | STAR
                | DISTINCT LVALUE
                | DISTINCT TAGS'''
    if t[1] == 'distinct':
        if t[2] == 'tags':
            restrict = 'true'
            t[0] =("DISTINCT m.tagname", 'true', ext_default)
        elif t[2] == 'uuid':
            t[0] = ("DISTINCT s.uuid", "true", ext_default)
        else:
            t[0] = ("DISTINCT m.tagval", "tagname = %s" % 
                     escape_string(t[2]), ext_default)
    else:
        select = "s.uuid, m.tagname, m.tagval"
        if t[1] == '*':
            restrict = 'true'
        else:
            def make_clause(x):
                if x == 'uuid':
                    return "tagname = 'Path'"
                else:
                    return "tagname = %s" % escape_string(x)
            restrict = ('(' + " OR ".join(map(make_clause, t[1])) + ')')
        t[0] = (select, restrict, ext_plural)

def p_data_clause(t):
    '''data_clause : DATA IN LPAREN NUMBER COMMA NUMBER RPAREN limit
                   | DATA BEFORE timeref limit
                   | DATA AFTER timeref limit'''
    if t[2] == 'in':
        method = 'data'
        start, end = t[4], t[6]
        limit = t[8]
        if limit[0] == None: limit[0] = 10000
    elif t[2] == 'before':
        method = 'prev'
        start, end = t[3], 0
        limit = t[4]
        if limit[0] == None: limit[0] = 1
    elif t[2] == 'after':
        method = 'next'
        start, end = t[3], 0
        limit = t[4]
        if limit[0] == None: limit[0] = 1

    t[0] = ("distinct(s.uuid), s.id", "true", 
            lambda streams: extract_data(streams, method, start, end, 
                                         limit[0], limit[1]))

def p_timeref(t):
    '''timeref : NUMBER 
               | NOW'''
    if t[1] == 'now':
        t[0] = str(int(time.time()) * 1000)
    else:
        t[0] = t[1]

def p_limit(t):
    '''limit : 
             | LIMIT NUMBER
             | STREAMLIMIT NUMBER
             | LIMIT NUMBER STREAMLIMIT NUMBER'''
    limit, slimit = [None, 10]
    if len(t) == 1:
        pass
    elif t[1] == 'limit':
        limit = t[2]
        if len(t) == 5:
            slimit = t[4]
    elif t[1] == 'streamlimit':
        slimit = t[2]
    t[0] = [limit, slimit]

def p_tag_list(t):
    '''tag_list : LVALUE
                | LVALUE COMMA tag_list'''
                
    if len(t) == 2:
        t[0] = [t[1]]
    else:
        t[0] = [t[1]] + t[3]

def p_set_list(t):
    '''set_list : LVALUE EQ QSTRING
                | LVALUE EQ QSTRING COMMA set_list'''
    if len(t) == 4:
        t[0] = [(t[1], t[3])]
    else:
        t[0] = [(t[1], t[3])] + t[5]

def merge_clauses(klass, lstmt, rstmt) :
    if type(lstmt) == klass and type(rstmt) == klass:
        return klass(lstmt.clauses.union(rstmt.clauses))
    elif type(lstmt) == klass:
        return klass(lstmt.clauses.union(set([rstmt])))
    elif type(rstmt) == klass:
        return klass(rstmt.clauses.union(set([lstmt])))
    else:
        return klass([lstmt, rstmt])

def p_statement(t):
    '''statement : statement_unary
                 | statement_binary
                 | LPAREN statement RPAREN
                 | statement AND statement
                 | statement OR statement
                 | NOT statement
                '''
    if len(t) == 2:
        t[0] = t[1]
    elif t[2] == 'and':
        t[0] = merge_clauses(qg.AndOperator, t[1], t[3])
    elif t[2] == 'or':
        t[0] = merge_clauses(qg.OrOperator, t[1], t[3])
    elif t[1] == 'not':
        t[0] = qg.NotOperator([t[2]])
    else:
        t[0] = t[2]

def p_statement_unary(t):
    '''statement_unary : HAS LVALUE'''
    if t[1] == 'has':
        t[0] = qg.Clause(qg.build_clause(t.parser.request, 
                                         "tagname = %s" % escape_string(t[2])))

def p_statement_binary(t):
    '''statement_binary : LVALUE EQ QSTRING
                        | LVALUE LIKE QSTRING
                        | LVALUE TILDE QSTRING
                        | LVALUE IN LPAREN statement RPAREN
    '''
    if t[2] == 'in':
        t[0] = qg.Clause(qg.build_clause(t.parser.request,
                                         """
  mi1.tagname = %s AND
  si1.uuid = mi1.tagval AND
  si1.id IN (%s)""" % (t[1], t[4]), ti='1'))
    elif t[1] == 'uuid':
        t[0] = qg.Clause(qg.build_clause(t.parser.request, "(si.uuid = %s)" %
                                         escape_string(t[3])))
    elif t[2] == '=':
        t[0] = qg.Clause(qg.build_clause(t.parser.request, "(tagname = %s AND tagval = %s)" % 
                                         (escape_string(t[1]), 
                                          escape_string(t[3]))))
    elif t[2] == 'like':
        t[0] = qg.Clause(qg.build_clause(t.parser.request, "(tagname = %s AND tagval LIKE %s)" % 
                         (escape_string(t[1]), 
                          escape_string(t[3]))))
    elif t[2] == '~':
        t[0] = qg.Clause(qg.build_clause(t.parser.request, "(tagname = %s AND tagval ~ E%s)" %
                         (escape_string(t[1]), 
                          escape_string(t[3]))))

def p_error(t):
    raise qg.QueryException("Syntax error at '%s'" % t.value, 400)

smapql_parser = yacc.yacc()

class QueryParser:
    """Class to manage parsing and extracting results from the
    database and readingdb"""
    def __init__(self, request): 
        self.parser = copy.copy(smapql_parser)
        self.parser.request = request

    def parse(self, s):
        return self.parser.parse(s, lexer=smapql_lex)

    def runquery(self, db, s):
        ext, q = self.parse(s)
        
        if not ext:
            d = db.runOperation(q)
            d.addCallback(lambda: [])
        else:
            d = db.runQuery(q)
        if ext:
            d.addCallback(ext)
        return d


if __name__ == '__main__':
    import os
    import readline
    import traceback
    import sys
    import pprint
    import settings as s
    import atexit
    from twisted.internet import reactor
    from twisted.enterprise import adbapi

    if len(sys.argv) != 2:
        print "\n\t%s <archiver conf>\n" % sys.argv[0]
        sys.exit(1)
    s.load(sys.argv[1])

    HISTFILE = os.path.expanduser('~/.smap-query-history')

    readline.parse_and_bind('tab: complete')
    readline.parse_and_bind('set editing-mode emacs')
    if hasattr(readline, "read_history_file"):
        try:
            readline.read_history_file(HISTFILE)
        except IOError:
            pass
    atexit.register(readline.write_history_file, HISTFILE)

    cp = adbapi.ConnectionPool(s.DB_MOD, # 'MySQLdb', 
                               host=s.DB_HOST,
                               database=s.DB_DB,
                               user=s.DB_USER,
                               password=s.DB_PASS,
                               cp_min=5, cp_max=15)

    class Request(object):
        pass

    request = Request()
    setattr(request, 'args', {'key' : ['jNiUiSNvb2A4ZCWrbqJMcMCblvcwosStiV71']})
    qp = QueryParser(request)

    def readquery():
        try:
            s = raw_input('query > ')   # Use raw_input on Python 2
            if s == '': 
                return readquery()
        except EOFError:
            return None
        except:
            traceback.print_exc()

        print s
        d = qp.runquery(cp, s)
        d.addCallback(lambda v: pprint.pprint(v))
        d.addCallback(lambda x: readquery())
        return d

    d = readquery()
    d.addCallbacks(lambda x: reactor.stop())
    reactor.run()

    cp.close()
