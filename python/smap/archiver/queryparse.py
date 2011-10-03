
import pgdb as sql
import operator

import querygen as qg
from smap.util import build_recursive

import ply
import ply.lex as lex
import ply.yacc as yacc
import copy

tokens = (
    'HAS', 'AND', 'OR', 'NOT', 'LIKE', 'DISTINCT', 'STAR',
    'LPAREN', 'RPAREN', 'COMMA', 'TAGS', 'SELECT', 'WHERE',
    'QSTRING', 'EQ', 'NUMBER', 'LVALUE'
    )

reserved = {
    'where' : 'WHERE',
    'distinct' : 'DISTINCT',
    'select' : 'SELECT',
    'tags' : 'TAGS',
    'has' : 'HAS',
    'and' : 'AND',
    'or' : 'OR',
    'not' : 'NOT',
    'like' : 'LIKE',
    }

t_LPAREN = r'\('
t_RPAREN = r'\)'
t_STAR = r'\*'
t_COMMA = r','
t_QSTRING = r'("([^"]|\\")*?")|\'([^"]|\\")*?\''
t_EQ = r'='

def t_LVALUE(t):
    r'[a-zA-Z][a-zA-Z0-9\/\%_\-]*'
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

def ext_plural(x):
    rv = {}
    for uuid, tagname, tagval in x:
        if not uuid in rv:
            rv[uuid] = {'uuid' : uuid}
        rv[uuid][tagname] = tagval
    return map(lambda x: build_recursive(x, suppress=[]), rv.itervalues())

def p_query(t):
    '''query : SELECT selector WHERE statement
             | SELECT selector'''
    if len(t) == 5:
        t[0] = t[2][2], ("""SELECT %s FROM metadata2 m, stream s 
              WHERE stream_id IN (%s) AND %s AND
                   s.id = m.stream_id""" % \
                             (t[2][0], qg.normalize(t[4]).render(), t[2][1]))
    else:
        t[0] = t[2][2], ("""SELECT %s FROM metadata2 m, stream s, subscription sub 
              WHERE s.id = m.stream_id AND s.subscription_id = sub.id
                 AND %s AND %s""" % 
                         (t[2][0], t[2][1], 
                          qg.build_authcheck(t.parser.request)))

def p_selector(t):
    '''selector : tag_list
                | STAR
                | DISTINCT LVALUE
                | DISTINCT TAGS'''
    if t[1] == 'distinct':
        if t[2] == 'tags':
            restrict = 'true'
            t[0] = ("DISTINCT m.tagname", 'true', ext_default)
        elif t[2] == 'uuid':
            t[0] = ("DISTINCT s.uuid", "true", ext_default)
        else:
            t[0] = ("DISTINCT m.tagval", "tagname = '%s'" % 
                    sql.escape_string(t[2]), ext_default)
    else:
        select = "s.uuid, m.tagname, m.tagval"
        if t[1] == '*':
            restrict = 'true'
        else:
            def make_clause(x):
                if x == 'uuid':
                    return "tagname = 'Path'"
                else:
                    return "tagname = '%s'" % sql.escape_string(x)
            restrict = ('(' + " OR ".join(map(make_clause, t[1])) + ')')
        t[0] = (select, restrict, ext_plural)

def p_tag_list(t):
    '''tag_list : LVALUE
                | LVALUE COMMA tag_list'''
    if len(t) == 2:
        t[0] = [t[1]]
    else:
        t[0] = [t[1]]+ t[3]

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
        t[0] = qg.AndOperator([t[1], t[3]])
    elif t[2] == 'or':
        t[0] = qg.OrOperator([t[1], t[3]])
    elif t[1] == 'not':
        t[0] = qg.NotOperator([t[2]])
    else:
        t[0] = t[2]

def p_statement_unary(t):
    '''statement_unary : HAS LVALUE'''
    if t[1] == 'has':
        t[0] = qg.Clause(qg.build_clause(t.parser.request, 
                                         "tagname = '%s'" % sql.escape_string(t[2])))

def p_statement_binary(t):
    '''statement_binary : LVALUE EQ QSTRING
                        | LVALUE LIKE QSTRING
    '''
    if t[1] == 'uuid':
        t[0] = qg.Clause(qg.build_clause(t.parser.request, "(s.uuid = '%s')" %
                                         sql.escape_string(t[3][1:-1])))
    elif t[2] == '=':
        t[0] = qg.Clause(qg.build_clause(t.parser.request, "(tagname = '%s' AND tagval = '%s')" % 
                                         (sql.escape_string(t[1]), 
                                          sql.escape_string(t[3][1:-1]))))
    elif t[2] == 'like':
        t[0] = qg.Clause (qg.build_clause(t.parser.request, "(tagname = '%s' AND tagval LIKE '%s')" % 
                          (sql.escape_string(t[1]), 
                           sql.escape_string(t[3][1:-1]))))

def p_error(t):
    print("Syntax error at '%s'" % t.value)

smapql_parser = yacc.yacc()

class QueryParser:
    def __init__(self, request):
        self.parser = copy.copy(smapql_parser)
        self.parser.request = request

    def parse(self, s):
        return self.parser.parse(s, lexer=smapql_lex)
    

if __name__ == '__main__':
    import os
    import readline
    import traceback
    import pgdb
    import sys
    import pprint
    import settings as s
    readline.parse_and_bind('tab: complete')
    readline.parse_and_bind('set editing-mode emacs')

    connection = pgdb.connect(host=s.MYSQL_HOST,
                          user=s.MYSQL_USER,
                          password=s.MYSQL_PASS,
                          database=s.MYSQL_DB)
    cur = connection.cursor()


    class Request(object):
        pass
    request = Request()
    setattr(request, 'args', {'private' : [], 
                              'key' : ['jNiUiSNvb2A4ZCWrbqJMcMCblvcwosStiV71']})

    qp = QueryParser(request)

    if not os.isatty(sys.stdin.fileno()):
        extractor, v = qp.parse(sys.stdin.read())
        cur.execute(v)
        pprint.pprint(extractor(cur.fetchall()))
    else:
        while True:
            try:
                s = raw_input('query > ')   # Use raw_input on Python 2
                if s == '': continue
            except EOFError:
                break

            try:
                extractor, v = qp.parse(s)
 
                if '-v' in sys.argv:
                    print v
           
                cur.execute(v)
                pprint.pprint(extractor(cur.fetchall()))
            except:
                traceback.print_exc()

    cur.close()
    connection.close()
