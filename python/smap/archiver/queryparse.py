
import pgdb as sql
import operator

import querygen as qg
# import querydata as dq
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
    'SET', 'TILDE',
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
    'Readings': 'DATA',
    'in' : 'IN',
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


def p_query(t):
    '''query : SELECT selector WHERE statement
             | SELECT selector
             | DELETE tag_list WHERE statement
             | DELETE WHERE statement
             | SET set_list WHERE statement
             '''
    if t[1] == 'select':
        sqlsel, datasel = t[2]
        if len(t) == 5:
            t[0] = sqlsel[2], ("""SELECT %s FROM metadata2 m, stream s 
              WHERE stream_id IN (%s) AND %s AND
                   s.id = m.stream_id""" % \
                                   (sqlsel[0], qg.normalize(t[4]).render(), sqlsel[1])), \
                                   datasel
        else:
            t[0] = sqlsel[2], ("""SELECT %s FROM metadata2 m, stream s, subscription sub 
              WHERE s.id = m.stream_id AND s.subscription_id = sub.id
                 AND %s AND %s""" % 
                               (sqlsel[0], sqlsel[1], 
                                qg.build_authcheck(t.parser.request))), datasel
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
                """ % delete_inner, \
                None
        else:
            # this alters the tags but doesn't touch the data
            t[0] = None, \
                ("""DELETE FROM metadata2 WHERE stream_id IN %s
                    AND (%s)""" % (delete_inner, 
                                   ' OR '.join(map(lambda x: "tagname = '%s'" % 
                                                   sql.escape_string(x), 
                                                   t[2])))),\
                                   None
    elif t[1] == 'set':
        #  set tags by calling the add_tag stored procedure with each
        #  new tag; this'll insert or update the database as
        #  appropriate
        tag_stmt = ','.join(map(lambda (t, v): \
                                    "add_tag(m.stream_id, '%s', '%s')" % 
                                (sql.escape_string(t), 
                                 sql.escape_string(v)), 
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
             qg.build_authcheck(t.parser.request, forceprivate=True)), \
               None


def p_selector(t):
    '''selector : tag_list
                | STAR
                | DISTINCT LVALUE
                | DISTINCT TAGS'''
    if t[1] == 'distinct':
        if t[2] == 'tags':
            restrict = 'true'
            t[0] = (("DISTINCT m.tagname", 'true', ext_default), None)
        elif t[2] == 'uuid':
            t[0] = (("DISTINCT s.uuid", "true", ext_default), None)
        else:
            t[0] = (("DISTINCT m.tagval", "tagname = '%s'" % 
                     sql.escape_string(t[2]), ext_default), None)
#     elif len(t) == 2 and t[1] != '*':
#         # get data
#         t[0] = (("DISTINCT s.uuid", "true", ext_default), t[1])
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
        t[0] = ((select, restrict, ext_plural), None)

# def p_data_clause(t):
#     '''data_clause : apply_fn IN LPAREN NUMBER COMMA NUMBER RPAREN'''
#     t[1].set_range(t[4], t[6])
#     t[0] = t[1]

# def p_apply_fn(t):
#     '''apply_fn : LVALUE LPAREN apply_fn RPAREN
#                 | LVALUE LPAREN apply_fn COMMA arg_list RPAREN
#                 | LVALUE LPAREN DATA RPAREN
#                 | LVALUE LPAREN DATA COMMA arg_list RPAREN
#                 '''
#     if isinstance(t[3], dq.DataQuery):
#         qobj = t[3]
#     else:
#         qobj = dq.DataQuery()
#     if len(t) == 5:
#         qobj.add_filter(t[1], [])
#     else:
#         qobj.add_filter(t[1], t[5])
#     t[0] = qobj

# def p_arg_list(t):
#     '''arg_list : QSTRING
#                 | NUMBER
#                 | QSTRING COMMA arg_list
#                 | NUMBER COMMA arg_list'''
#     p_tag_list(t)

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
                                         "tagname = '%s'" % sql.escape_string(t[2])))

def p_statement_binary(t):
    '''statement_binary : LVALUE EQ QSTRING
                        | LVALUE LIKE QSTRING
                        | LVALUE TILDE QSTRING
                        | LVALUE IN LPAREN statement RPAREN
    '''
    if t[2] == 'in':
        t[0] = qg.Clause(qg.build_clause(t.parser.request,
                                         """
  mi1.tagname = '%s' AND
  si1.uuid = mi1.tagval AND
  si1.id IN (%s)""" % (t[1], t[4]), ti='1'))
    elif t[1] == 'uuid':
        t[0] = qg.Clause(qg.build_clause(t.parser.request, "(si.uuid = '%s')" %
                                         sql.escape_string(t[3])))
    elif t[2] == '=':
        t[0] = qg.Clause(qg.build_clause(t.parser.request, "(tagname = '%s' AND tagval = '%s')" % 
                                         (sql.escape_string(t[1]), 
                                          sql.escape_string(t[3]))))
    elif t[2] == 'like':
        t[0] = qg.Clause(qg.build_clause(t.parser.request, "(tagname = '%s' AND tagval LIKE '%s')" % 
                         (sql.escape_string(t[1]), 
                          sql.escape_string(t[3]))))
    elif t[2] == '~':
        t[0] = qg.Clause(qg.build_clause(t.parser.request, "(tagname = '%s' AND tagval ~ E'%s')" %
                         (sql.escape_string(t[1]), 
                          sql.escape_string(t[3]))))

def p_error(t):
    print("Syntax error at '%s'" % t.value)

smapql_parser = yacc.yacc()

class QueryParser:
    def __init__(self, request):
        self.parser = copy.copy(smapql_parser)
        self.parser.request = request

    def parse(self, s):
        return self.parser.parse(s, lexer=smapql_lex)
    

def runquery(cur, q):
    extractor, v, datagetter = qp.parse(s)

    if '-v' in sys.argv:
        print v

    if '-n' in sys.argv:
        return
    
    cur.execute(v)
    if datagetter:
        return datagetter.execute(None, extractor(cur.fetchall()))
    elif extractor:
        return extractor(cur.fetchall())

if __name__ == '__main__':
    import os
    import readline
    import traceback
    import pgdb
    import sys
    import pprint
    import settings as s
    import atexit
    HISTFILE = os.path.expanduser('~/.smap-query-history')

    readline.parse_and_bind('tab: complete')
    readline.parse_and_bind('set editing-mode emacs')
    if hasattr(readline, "read_history_file"):
        try:
            readline.read_history_file(HISTFILE)
        except IOError:
            pass
    atexit.register(readline.write_history_file, HISTFILE)
        
    connection = pgdb.connect(host=s.MYSQL_HOST,
                              user=s.MYSQL_USER,
                              password=s.MYSQL_PASS,
                              database=s.MYSQL_DB)
    cur = connection.cursor()


    class Request(object):
        pass
    request = Request()
    setattr(request, 'args', {'key' : ['jNiUiSNvb2A4ZCWrbqJMcMCblvcwosStiV71']})
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
                v = runquery(cur, s)
                pprint.pprint(v)
            except EOFError:
                break
            except:
                traceback.print_exc()

    cur.close()
    connection.close()
