"""
Copyright (c) 2011, 2012, Regents of the University of California
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions 
are met:

 - Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
 - Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the
   distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL 
THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED 
OF THE POSSIBILITY OF SUCH DAMAGE.
"""
"""
@author Stephen Dawson-Haggerty <stevedh@eecs.berkeley.edu>
"""

import os
import operator
import time
import datetime
import inspect
import logging
import collections
import re

from twisted.internet import defer
from twisted.python import log

from smap import operators
from smap.util import build_recursive, is_string, flatten, SetDict 
from smap import sjson as json
from smap.contrib import dtutil

from smap.archiver.data import escape_string
from smap.archiver.querydata import extract_data
from smap.archiver import querygen as qg
from smap.archiver import data, stream, help, ast, consumers

import ply
import ply.lex as lex
import ply.yacc as yacc
import copy

tokens = (
    'HAS', 'AND', 'OR', 'NOT', 'LIKE', 'DISTINCT',
    'TAGS', 'SELECT', 'WHERE',
    'QSTRING','NUMBER', 'LVALUE', 'IN', 'DATA', 'DELETE',
    'SET', 'TILDE', 'BEFORE', 'AFTER', 'NOW', 'LIMIT', 'STREAMLIMIT',
    'APPLY', 'TO', 'AS', 'GROUP', 'BY', 'HELP', 'ALL', 
    'LTE', 'GTE', 'NE'
    )

precedence = (
    ('left', 'LIKE', 'TILDE', 'IN'),
    ('left', 'AND'),
    ('left', 'OR'),
    ('right', '='),
    ('right', 'NOT'),
    ('left', ','),
    ('left', '+'),
    ('left', '-'),
    ('left', '*'),
    ('left', '^'),
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
    'apply' : 'APPLY',
    'to' : 'TO',
    'as' : 'AS',
    'group' : 'GROUP',
    'by' : 'BY',
    'help' : 'HELP',
    'all' : 'ALL',
    }
literals = '()[]*^.,<>=+-/'

time_units = re.compile('^(d|days?|h|hours?|m|minutes?|s|seconds?)$')
def get_timeunit(t):
    if not time_units.match(t):
        raise qg.QueryException("Invalid timeunit: %s" % t)
    if t.startswith('d'): return 'days'
    elif t.startswith('h'): return 'hours'
    elif t.startswith('m'): return 'minutes'
    elif t.startswith('s'): return 'seconds'

def t_CMP(t):
    r'(<=)|(>=)|(!=)'
    t.type = {
        '<=' : 'LTE',
        '>=' : 'GTE',
        '!=' : 'NE'}[t.value]
    return t

def t_QSTRING(t):
    r'("[^"\\]*?(\\.[^"\\]*?)*?")|(\'[^\'\\]*?(\\.[^\'\\]*?)*?\')'    
    if t.value[0] == '"':
        t.value = t.value[1:-1].replace('\\"', '"')
    elif t.value[0] == "'":
        t.value = t.value[1:-1].replace("\\'", "'")
    return t

def t_LVALUE(t):
    r'[a-zA-Z\~\$\_][a-zA-Z0-9\/\%_\-]*'
    t.type = reserved.get(t.value, 'LVALUE')
    return t

def t_NUMBER(t):
    r'([+-]?([0-9]*\.)?[0-9]+)'
    if '.' in t.value:
        try:
            t.value = float(t.value)
        except ValueError:
            print "Invalid floating point number", t.value
            t.value = 0
    else:
        try:
            t.value = int(t.value)
        except ValueError:
            print "Integer value too large %d", t.value
            t.value = 0
        
    return t
is_number = lambda x: isinstance(x, int) or isinstance(x, float)

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

def ext_non_null(x):
    return filter(None, ext_default(x))

def ext_deletor(x):
    data.del_streams(map(operator.itemgetter(0), x))
    return map(operator.itemgetter(1), x)

def ext_plural(tags, vals):
    return [build_recursive(dict(zip(tags, v)), suppress=[]) for v in vals]

def ext_recursive(vals):
    return [build_recursive(x[0], suppress=[]) for x in vals]

TIMEZONE_PATTERNS = [
    "%m/%d/%Y",
    "%m/%d/%Y %H:%M",
    "%Y-%m-%dT%H:%M:%S",
    ]
def parse_time(ts):
    for pat in TIMEZONE_PATTERNS:
        try:
            return dtutil.strptime_tz(ts, pat, tzstr='America/Los_Angeles')
        except ValueError:
            continue
    raise ValueError("Invalid time string:" + ts)

def make_select_rv(t, sel, wherestmt='true'):
    return sel.extract, ("""SELECT %s FROM stream s, subscription sub
              WHERE (%s) AND (%s) AND
              sub.id = s.subscription_id""" % 
                         (sel.select, 
                          wherestmt,
                          qg.build_authcheck(t.parser.request)))

def build_setstring(setvals, wherevals):
    #  set tags 
    regex = None
    for stmt in wherevals:
        if stmt.op == ast.Statement.OP_REGEX:
            if regex == None:
                regex = stmt
            else:
                raise qg.QueryException("Too many regexes in set.  Only one supported!")

    if regex == None:
        new_tags = ' || '.join(map(lambda (t,v): "hstore(%s, %s)" % 
                                   (escape_string(t), escape_string(v)),
                                   setvals))
    else:
        new_tags = ' || '.join(map(lambda (t,v): "hstore(%s, regexp_replace(metadata -> %s, '^.*%s.*$', %s))" % 
                                   (escape_string(t), 
                                    regex.args[0],
                                    regex.args[1][1:-1].replace('\\\\', '\\'),
                                    escape_string(v).replace('\\\\', '\\')),
                                   setvals))
    return new_tags;


# top-level statement dispatching
def p_query(t):
    """query : SELECT selector WHERE statement
             | SELECT selector
             | SELECT data_clause WHERE statement
             | DELETE tag_list WHERE statement
             | DELETE WHERE statement
             | SET set_list WHERE statement
             | APPLY apply_statement
             | HELP
             | HELP LVALUE
             """
    if t[1] == 'select': 
        if len(t) == 5:
            t[0] = make_select_rv(t, t[2], t[4].render())
        elif len(t) == 3:
            t[0] = make_select_rv(t, t[2])
        
    elif t[1] == 'delete':
        # a new delete inner statement enforces that we only delete
        # things which we have the key for.
        if t[2] == 'where':
            # delete the whole stream, gone.  this also deletes the
            # data in the backend readingdb.
            t[0] = ext_deletor, \
                """DELETE FROM stream WHERE id IN (
                     SELECT s.id FROM stream s, subscription sub 
                     WHERE (%(restrict)s) AND s.subscription_id = sub.id AND 
                     (%(auth)s)
                   ) RETURNING id, uuid
                """ % { 
                'restrict': t[3].render(),
                'auth': qg.build_authcheck(t.parser.request, forceprivate=True) 
                }
        else:
            # this alters the tags but doesn't touch the data
            del_tags = ', '.join(map(escape_string, t[2]))
            q = "UPDATE stream SET metadata = metadata - ARRAY[" + del_tags + \
                "] WHERE id IN " + \
                "(SELECT s.id FROM stream s, subscription sub " + \
                "WHERE (" + t[4].render() + ") AND s.subscription_id = sub.id AND " + \
                qg.build_authcheck(t.parser.request, forceprivate=True)  + ")"
            t[0] = None, q

    elif t[1] == 'set':
        new_tags = build_setstring(t[2], t[4])
        q = "UPDATE stream SET metadata = metadata || " + new_tags + \
            " WHERE id IN "  + \
            "(SELECT s.id FROM stream s, subscription sub " + \
            "WHERE (" + t[4].render() + ") AND s.subscription_id = sub.id AND " + \
            qg.build_authcheck(t.parser.request, forceprivate=True)  + ")"
        t[0] = None, q

    elif t[1] == 'apply':
        t[0] = t[2]
    elif t[1] == 'help':
        if len(t) == 2:
            t[0] = help.help(), None
        else:
            t[0] = help.help(t[2]), None

def add_formula_restrictions(c_restrict, f_restrict):
    extra = []
    for k, v in SetDict(f_restrict):
        if k != 'uuid':
            extra.append('((s.metadata -> %s) ~ %s)' % 
                         (escape_string(k), escape_string(v)))
        else:
            extra.append('(s.uuid = %s)' % escape_string(v))
    if len(extra):
        return c_restrict + ' AND (' + ' OR '.join(extra) + ')'
    else:
        return c_restrict

# apply a sequence of operators to data
def p_apply_statement(t):
    """apply_statement  : formula_pipe TO data_clause WHERE statement
                        | formula_pipe TO data_clause WHERE statement GROUP BY tag_list
    """
    print "Existing restrictions", t[5].render()
    restrict = add_formula_restrictions(t[5].render(), t[1].restrict)
    tag_extractor, tag_query = make_select_rv(t, 
                                              make_tag_select('*'), 
                                              restrict)
    _, data_query = make_select_rv(t, t[3], restrict)

    # this does not make me feel good.    
    data_extractor = lambda x: x
    if len(t) > 7: group = t[8]
    else: group = None
    print "Extra restrictions", t[1].restrict
    app = stream.OperatorApplicator(t[1].ast, t[3].dparams,
                                    consumers.make_outputfilter(t.parser.request), 
                                    group=group)
    t[0] = ([app.start_processing, tag_extractor, data_extractor], 
            [None, tag_query, data_query])


selector = collections.namedtuple('selector', 'select extract')
def make_tag_select(tagset):
    if '*' in tagset:
        return selector("s.metadata || hstore('uuid', s.uuid)", ext_recursive)
    else:
        if 'uuid' in tagset:
            tagset.add('Path')
        def make_clause(x):
            if x == 'uuid':
                return "(s.uuid)"
            else:
                return "(s.metadata -> %s)" % escape_string(x)
    tags = list(tagset)
    select = ', '.join(map(make_clause, tags))
    return selector(select, lambda vals: ext_plural(tags, vals))

# make a tag selector: the things to select.  this is how you specify
# what tags you want back.
def p_selector(t):
    """selector : tag_list
                | '*'
                | DISTINCT LVALUE
                | DISTINCT """
    if t[1] == 'distinct':
        if len(t) == 2:
            t[0] = selector("DISTINCT skeys(s.metadata)", ext_non_null)
        elif t[2] == 'uuid':
            t[0] = selector("DISTINCT s.uuid", ext_non_null)
        else:
            t[0] = selector("DISTINCT (s.metadata -> %s)" % escape_string(t[2]),
                            ext_non_null)
    else:
        t[0] = make_tag_select(t[1])

data_selector = collections.namedtuple("data_selector", 
                                       "select extract dparams")
# make a data selector: what data to load.
def p_data_clause(t):
    """data_clause : DATA IN '(' timeref ',' timeref ')' limit
                   | DATA IN timeref ',' timeref limit
                   | DATA BEFORE timeref limit
                   | DATA AFTER timeref limit"""
    if t[2] == 'in':
        off = 1 if t[3] == '(' else 0
        method = 'data'
        start, end = t[off+3], t[off+5]
        limit = t[2*off+6]
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
    if limit[0] == -1: limit[0] = 1e7

    t.parser.request.args.update({
        'starttime' : [start],
        'endtime' : [end],
        'limit' : [limit[0]],
        'streamlimit' : [limit[1]],
        })

    t[0] = data_selector("distinct(s.uuid), s.id",
                         lambda streams: data.data_load_result(t.parser.request,
                                                               method,
                                                               streams,
                                                               ndarray=False,
                                                               as_smapobj=True,
                                                               send=True), {
            'start' : start,
            'end' : end,
            'method' : method,
            'chunk': None,
            'limit' : limit })

# an absolute time reference.  can be a unix timestamp, a date string,
# or "now"
def p_timeref(t):
    """timeref : abstime
               | abstime reltime"""
    t[0] = t[1]
    if len(t) == 2:
        ref = t[1]
    else:
        ref = t[1] + t[2]
    t[0] = dtutil.dt2ts(ref) * 1000

def p_abstime(t):
    """abstime : NUMBER 
               | QSTRING
               | NOW"""
    if t[1] == 'now':
        t[0] = dtutil.now()
    elif type(t[1]) == type(''):
        t[0] = parse_time(t[1])
    else:
        t[0] = dtutil.ts2dt(t[1] / 1000)

def p_reltime(t):
    """reltime : NUMBER LVALUE
               | NUMBER LVALUE reltime"""
    timeunit = get_timeunit(t[2])
    delta = datetime.timedelta(**{timeunit: t[1]})
    if len(t) == 3:
        t[0] = delta
    else:
        t[0] = t[3] + delta


# limit the amount of data returned by number of streams and number of
# points
def p_limit(t):
    """limit : 
             | LIMIT NUMBER
             | STREAMLIMIT NUMBER
             | LIMIT NUMBER STREAMLIMIT NUMBER"""
    limit, slimit = [None, 1000]
    if len(t) == 1:
        pass
    elif t[1] == 'limit':
        limit = t[2]
        if len(t) == 5:
            slimit = t[4]
    elif t[1] == 'streamlimit':
        slimit = t[2]
    t[0] = [limit, slimit]

def make_operator(name, args, where=None):
    if where == None:
        return stream.get_operator(name, args)
    else:
        return operators.make_composition_operator(
            [where, stream.get_operator(name, args)])

def p_arg_clause(t):
    """arg_clause : '(' arg_list ')'
                  | 
    """
    if len(t) > 1:
        t[0] = t[2]
    else:
        t[0] = (list(), dict())

def empty_arg_list():
    return (list(), dict())

def p_arg_list(t):
    """arg_list     : 
                    | call_argument
                    | call_argument ',' arg_list
                     """
    if len(t) == 1:
        t[0] = empty_arg_list()
        return
    if len(t) == 2:
        alist = empty_arg_list()
    else:
        alist = t[3]

    if t[1][0] == 'arg':
        alist[0].reverse()
        alist[0].append(t[1][1])
        alist[0].reverse()
    elif t[1][0] == 'kwarg':
        alist[1].update(t[1][1])
    t[0] = alist
        
def p_call_argument(t):
    """call_argument   : QSTRING
                       | NUMBER
                       | LVALUE '=' NUMBER
                       | LVALUE '=' QSTRING
                       | formula_pipe
                       | """
    if len(t) == 4:
        t[0] = ('kwarg', {
            t[1] : t[3]
            })
    else:
        if isinstance(t[1], formula_pipe):
            t[0] = ('arg', t[1].ast)
        else:
            t[0] = ('arg', t[1])

def p_tag_list(t):
    """tag_list : LVALUE
                | LVALUE ',' tag_list"""
                
    if len(t) == 2:
        t[0] = set([t[1]])
    else:
        t[3].add(t[1])
        t[0] = t[3]

def p_set_list(t):
    """set_list : LVALUE '=' QSTRING
                | LVALUE '=' QSTRING ',' set_list"""
    if len(t) == 4:
        t[0] = [(t[1], t[3])]
    else:
        t[0] = [(t[1], t[3])] + t[5].render()

def p_statement(t):
    """statement : statement_unary
                 | statement_binary
                 | '(' statement ')'
                 | statement AND statement
                 | statement OR statement
                 | NOT statement
                """
    if len(t) == 2:
        t[0] = t[1]
    elif t[2] == 'and':
        t[0] = ast.Statement(ast.Statement.OP_AND, t[1], t[3])
    elif t[2] == 'or':
        t[0] = ast.Statement(ast.Statement.OP_OR, t[1], t[3])
    elif t[1] == 'not':
        t[0] = ast.Statement(ast.Statement.OP_NOT, t[2])
    else:
        t[0] = t[2]

def p_statement_unary(t):
    """statement_unary : HAS LVALUE"""
    if t[1] == 'has':
        t[0] = ast.Statement(ast.Statement.OP_HAS, t[2])

def p_statement_binary(t):
    """statement_binary : LVALUE '=' QSTRING
                        | LVALUE LIKE QSTRING
                        | LVALUE TILDE QSTRING
    """
    if t[1] == 'uuid':
        t[0] = ast.Statement(ast.Statement.OP_UUID, t[2], t[3])
    else:
        if t[2] == '=': 
            t[0] = ast.Statement(ast.Statement.OP_EQUALS, t[1], t[3])
        elif t[2] == 'like':
            t[0] = ast.Statement(ast.Statement.OP_LIKE, t[1], t[3])
        elif t[2] == '~':
            t[0] = ast.Statement(ast.Statement.OP_REGEX, t[1], t[3])


formula = collections.namedtuple('formula', 'ast restrict')
formula_pipe = collections.namedtuple('formula', 'ast restrict mapping')
def p_formula(t):
    """formula : formula_where_clause
               | LVALUE arg_clause formula_where_clause
               | formula_multiply
               | formula_add
               | formula_subtract
               | formula_divide
               | formula_power
               | formula_comparator
    """
    if len(t) == 2:
        t[0] = t[1]
    else:
        if t[1] == 'rename':
            restrict = [('rename', t[2][0])]
        else:
            restrict = []
        t[0] = formula(ast.nodemaker(make_operator(t[1], t[2]), t[3].ast),
                       restrict + t[3].restrict)

def rename_restrictions(tags, mapping):
    """Process tag renames for a formula pipe"""
    new_tags = []
    for name, value in reversed(tags):
        if name == 'rename':
            if value[0] in mapping:
                mapping[value[1]] = mapping[value[0]]
                del mapping[value[0]]
            else:
                mapping[value[1]] = value[0]
        elif name in mapping:
            new_tags.append((mapping[name], value))
        else:
            new_tags.append((name, value))
    new_tags.reverse()
    return new_tags, mapping

def p_formula_pipe(t):
    """formula_pipe   : formula
                      | formula '<' formula_pipe"""
    if len(t) == 2:
        tree = t[1].ast
        restrict = t[1].restrict
        mapping = {}
    else:
        tree = ast.nodemaker(t[1].ast, t[3].ast)
        restrict = t[1].restrict + t[3].restrict
        mapping = t[3].mapping
    restrict, mapping = rename_restrictions(restrict, mapping)
    t[0] = formula_pipe(tree, restrict, mapping)
 
# def p_formula_list(t):
#     """formula_list : formula 
#                     | formula ',' formula_list
#     """
#     if len(t) == 2:
#         t[0] = [t[1]]
#     else:
#         t[0] = [t[1]] + t[3]

def p_formula_where_clause(t):
    """formula_where_clause : '[' LVALUE '.' QSTRING ']'
                            | '[' formula ']'
                            | ALL
                            | QSTRING
                            | 
    """
    if len(t) == 6:
        t[0] = formula(ast.leafmaker(stream.get_operator('w', ([t[2], t[4]], {}))),
                       [(t[2], t[4])])
    elif len(t) == 4:
        t[0] = t[2]
    elif len(t) == 2 and t[1] == 'all':
        t[0] = formula(ast.leafmaker(stream.get_operator('w', (['uuid', '.*'], {}))),
                       [])
    elif len(t) == 2:
        t[0] = formula(ast.leafmaker(stream.get_operator('w', (['x', t[1]], {}))),
                       [('x', t[1])])
    else:
        t[0] = formula(ast.leafmaker(stream.get_operator('null', ([], {}))), [])

def p_formula_multiply(t):
    """formula_multiply : NUMBER '*' formula
                        | formula '*' NUMBER
                        | NUMBER '*' NUMBER
                        | formula '*' formula
    """
    if is_number(t[1]) and is_number(t[3]):
        t[0] = t[1] * t[3]
    elif is_number(t[1]):
        t[0] = formula(ast.nodemaker(stream.get_operator('multiply', ([t[1]], {})), t[3].ast),
                       t[3].restrict)
    elif is_number(t[3]):
        t[0] = formula(ast.nodemaker(stream.get_operator('multiply', ([t[3]], {})), t[1].ast),
                       t[1].restrict)
    else:
        t[0] = formula(ast.nodemaker(operators.make_composition_operator(
                    [stream.get_operator('paste', ([], {'sort': None})),
                     stream.get_operator('product', ([], {'axis': 1}))]),
                                     t[1].ast, t[3].ast),
                       t[1].restrict + t[3].restrict)

def p_formula_add(t):
    """formula_add : NUMBER '+' NUMBER
                   | NUMBER '+' formula
                   | formula '+' NUMBER
                   | formula '+' formula
    """
    if is_number(t[1]) and is_number(t[3]):
        t[0] = t[1] + t[3]
    elif is_number(t[1]):
        t[0] = formula(ast.nodemaker(stream.get_operator('add', ([t[1]], {})), t[3].ast),
                       t[3].restrict)
    elif is_number(t[3]):
        t[0] = formula(ast.nodemaker(stream.get_operator('add', ([t[3]], {})), t[1].ast),
                       t[3].restrict)
    else:
        t[0] = formula(ast.nodemaker(operators.make_composition_operator(
                    [stream.get_operator('paste', ([], {'sort': None})),
                     stream.get_operator('sum', ([], {'axis': 1}))]),
                                     t[1].ast, t[3].ast),
                       t[1].restrict + t[3].restrict)

def p_formula_subtract(t):
    """formula_subtract : NUMBER '-' NUMBER
                        | formula '-' NUMBER
                        | formula '-' formula
    """
    if is_number(t[1]) and is_number(t[3]):
        t[0] = t[1] - t[3]
    elif is_number(t[1]):
        t[0] = formula(ast.nodemaker(stream.get_operator('add', ([t[1]], {})), t[3].ast),
                       t[3].restrict)
    elif is_number(t[3]):
        t[0] = formula(ast.nodemaker(stream.get_operator('add', ([- t[3]], {})), t[1].ast),
                       t[1].restrict)
    else:
        t[0] = formula(ast.nodemaker(operators.make_composition_operator(
                    [stream.get_operator('paste', ([], {'sort': None})),
                     stream.get_operator('diff', ([], {'axis': 1}))]),
                                     t[3].ast, t[1].ast),
                       t[3].restrict + t[1].restrict)

def p_formula_divide(t):
    """formula_divide : formula '/' NUMBER"""
    t[0] = formula(ast.nodemaker(stream.get_operator('multiply', ([1. / t[3]], {})), t[1].ast),
                   t[1].restrict)

def p_formula_power(t):
    """formula_power : formula '^' NUMBER"""
    t[0] = formula(ast.nodemaker(stream.get_operator('power', ([t[3]], {})), t[1].ast),
                   t[1].restrict)

cmp_names = {
    '>' : 'greater',
    '<' : 'less',
    '!=' : 'not_equal',
    '>=' : 'greater_equal',
    '<=' : 'less_equal',
    }

def p_formula_comparator(t):
    """formula_comparator : formula comparator NUMBER
                          | NUMBER comparator formula
    """
    if is_number(t[1]):
        pass
    else:
        # have to initialize the comparison operator with an
        # appropriate inner AST node.  usually this is done by the
        # parser...
        cmp = ast.nodemaker(stream.get_operator(cmp_names[t[2]], ([t[3]], {})),
                            ast.leafmaker(stream.get_operator('null', ([], {}))))
        t[0] = formula(ast.nodemaker(stream.get_operator('nonzero', ([cmp], {})), t[1].ast),
                       t[1].restrict)

# '<'
def p_comparator(t):
    """comparator : '>'
                  | LTE
                  | GTE
                  | NE
    """
    t[0] = t[1]
    
def p_error(t):
    raise qg.QueryException("Syntax error at '%s'" % t.value, 400)

smapql_parser = yacc.yacc(tabmodule='arq_tab',
                          outputdir=os.path.dirname(__file__),
                          debugfile='/dev/null',
                          debuglog=logging.getLogger('ply-debug'),
                          errorlog=logging.getLogger('ply-errors'))

def parse_opex(exp):
    global opex_parser
    try:
        opex_parser
    except NameError:
        opex_parser = yacc.yacc(start="formula_pipe", 
                                tabmodule='opex_tab.py',
                                debugfile='/dev/null',
                                debuglog=logging.getLogger('ply-debug'),
                                errorlog=logging.getLogger('ply-errors'))
    return opex_parser.parse(exp)

class QueryParser:
    """Class to manage parsing and extracting results from the
    database and readingdb"""
    def __init__(self, request): 
        self.parser = copy.copy(smapql_parser)
        self.parser.request = request

    def parse(self, s):
        return self.parser.parse(s, lexer=smapql_lex)

    def runquery(self, db, s, run=True, verbose=False):
        ext, q = self.parse(s)
        if is_string(ext):
            return defer.succeed(ext)
        elif not isinstance(q, list):
            q = [None, q]
            ext = [None, ext]

        if verbose:
            print q[1]
        if not run: return defer.succeed([])
        
        deferreds = []

        for ext_, q_ in zip(ext[1:], q[1:]):
            def print_time(result, start):
                logging.getLogger('stats').info("Query took %0.6fs" % (time.time() - start))
                return result
            if not ext_:
                d = db.runOperation(q_)
                d.addCallback(print_time, time.time())
                d.addCallback(lambda _: [])
            else:
                d = db.runQuery(q_)
                d.addCallback(print_time, time.time())
                d.addCallback(ext_)

            deferreds.append(d)

        if len(deferreds) > 1:
            d = defer.DeferredList(deferreds)
            if ext[0]:
                d.addCallback(ext[0])
        else:
            d = deferreds[0]

        return d


if __name__ == '__main__':
    import os
    import readline
    import traceback
    import sys
    import pprint
    import settings as s
    import data
    import atexit
    from twisted.internet import reactor
    from twisted.enterprise import adbapi
    from optparse import OptionParser

    logging.basicConfig()
 
    # pull out options
    usage = "usage: %prog [options] archiver-config.ini"
    parser = OptionParser(usage=usage)
    parser.add_option("-n", "--no-action", dest="run", 
                      action="store_false", default=True,
                      help="don't perform queries")
    parser.add_option("-v", "--verbose", dest="verbose", 
                      action="store_true", default=False,
                      help="print generated SQL")
    parser.add_option("-k", "--keys", dest="keys",
                      default="",
                      help="comma-separated list of keys to use in query")
    parser.add_option("-p", "--private", dest="private",
                      default=False, action="store_true",
                      help="request only private results")
    opts, args = parser.parse_args()
    
    if len(args) != 1:
        parser.print_help()
        sys.exit(1)

    s.conf = s.load(args[0])

    # set up readline
    HISTFILE = os.path.expanduser('~/.smap-query-history')
    readline.parse_and_bind('tab: complete')
    readline.parse_and_bind('set editing-mode emacs')
    if hasattr(readline, "read_history_file"):
        try:
            readline.read_history_file(HISTFILE)
        except IOError:
            pass
    atexit.register(readline.write_history_file, HISTFILE)

    cp = adbapi.ConnectionPool(s.conf['database']['module'],
                               host=s.conf['database']['host'],
                               database=s.conf['database']['db'],
                               user=s.conf['database']['user'],
                               password=s.conf['database']['password'],
                               port=s.conf['database']['port'],
                               cp_min=1, cp_max=1)

    # make a fake request to give the parser with whatever
    # command-line options we need.
    class Request(object):
        def write(self, data):
            try:
                pprint.pprint(json.loads(data))
            except:
                print data

        def finish(self):
            pass

        def registerProducer(self, a1, a2):
            pass

        def unregisterProducer(self):
            pass

    request = Request()
    args = {}
    if opts.keys: args['key'] = opts.keys.split(',')
    if opts.private: args['private'] = []
    setattr(request, 'args', args)

    # make a parser and start reading from the console
    qp = QueryParser(request)

    def readquery():
        try:
            s = raw_input('query > ')   # Use raw_input on Python 2
            if s == '': 
                return readquery()
        except EOFError:
            return reactor.callFromThread(reactor.stop)
        except:
            traceback.print_exc()
            return readquery()
            
        d = qp.runquery(cp, s, verbose=opts.verbose, run=opts.run)
        d.addCallback(lambda v: pprint.pprint(v))
        d.addCallback(lambda x: readquery())
        return d

    d = readquery()
    reactor.run()

    cp.close()
