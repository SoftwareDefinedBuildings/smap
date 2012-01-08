
import time
import operator

from data import escape_string
from smap import core

def build_authcheck(request, ti='', forceprivate=False):
    """Build an SQL WHERE clause which enforces access restrictions.
    Will pull any credentials out of the request object passed in.
    """
    if not 'private' in request.args and not forceprivate:
        query = "(sub%s.public " % ti
    else:
        query = "(false "
    if 'key' in request.args:
        query += 'OR ' + ' OR '.join(["sub.key = %s" % escape_string(x + ti)
                                      for x in request.args['key']])
    query += ")"
    return query

def build_clause(request, clause, ti=''):
    """Build an "inner query" -- a query which yields a list of stream
    ids (indexes in the stream table).  These match the identifiers
    used in the reading db, or can be used as part of a join.  The
    query performs auth checks and will check for the tags specified.
    """
    # the inner query builds a list of streams matching all the
    # clauses which we can then select from

    # perform the auth check in the inner query to give us the
    # most selectivity and avoid returning rows which the user
    # can't access.
    inner_query = ("""
(SELECT stream_id AS cnt
FROM metadata2 mi%(ti)s, subscription sub%(ti)s, stream si%(ti)s
WHERE (%(clause)s) AND """ + build_authcheck(request, ti) + """ AND
   mi%(ti)s.stream_id = si%(ti)s.id AND si%(ti)s.subscription_id = sub%(ti)s.id)
""") % {'clause' : clause, 'ti' : ti}
    return inner_query

class QueryException(core.SmapException):
    pass

class Operator(object):
    """Represent a boolean operator: not, or, and

    Operators have a "render" method which produces SQL
    """
    def __init__(self, clauses=None):
        if not clauses:
            self.clauses = set()
        elif hasattr(clauses, '__iter__'):
            self.clauses = set(clauses)
        else:
            self.clauses = set([clauses])


class Clause(str):
    """A clause is an atom in a a boolean sentence.  In order for
    rendering to work, these must be sql which evaluates to sets of
    streamids"""
    def render(self):
        return self


class AndOperator(Operator):
    """ "and" a set of clauses together
    """
    def check_not(self):
        or_exps = [x.check_not() for x in self.clauses if type(x) == OrOperator]
        and_exps = [x.check_not() for x in self.clauses if type(x) == AndOperator]
        not_exps = [x for x in self.clauses if type(x) == NotOperator]
        clause_exps = [x for x in self.clauses if type(x) == Clause]

        new_exp = set(or_exps + and_exps + not_exps + clause_exps)

        return AndOperator(new_exp)
        
    def render(self):
        not_clauses = filter(lambda x: type(x) == NotOperator, self.clauses)
        and_clauses = self.clauses - set(not_clauses)
        not_transform = OrOperator(map(lambda x: iter(x.clauses).next(), not_clauses))

        rv = ['( (']
        rv.append(' INTERSECT '.join(map(lambda x: x.render(), and_clauses)))
        rv.append(')')
        if len(not_clauses) > 0:
            rv.append('EXCEPT')
            rv.append(not_transform.render())
        rv.append(')')
        return ' '.join(rv)

    def __str__(self):
        return '(' + ' AND '.join(map(str, self.clauses)) + ')'

class OrOperator(Operator):
    """The or operator is a bit complicated because if there are
    "not"ed subclauses, we can't just union them together.  We use
    demorgans rule and convert them into INTERSECT/EXCEPT and then
    negate the result.
    """
    def __str__(self):
        return '(' + ' OR '.join(map(str, self.clauses)) + ')'

    def check_not(self):
        not_clauses = filter(lambda x: type(x) == NotOperator, self.clauses)
        if len(not_clauses) > 0:
            # if there are any negations, group them and use the
            # INTERSECT/EXCEPT method using de morgans rule

            # negate the bare expressions
            or_clauses = map(NotOperator, self.clauses - set(not_clauses))
            # and remove the negation from the negated ones
            not_clauses = map(lambda x: iter(x.clauses).next(), not_clauses)
            # then and the result
            return NotOperator(AndOperator(or_clauses + not_clauses))
        else:
            return self

    def render(self):
        not_clauses = filter(lambda x: type(x) == NotOperator, self.clauses)
        if len(not_clauses) > 0:
            # if there are any negations, group them and use the
            # INTERSECT/EXCEPT method using de morgans rule

            # negate the bare expressions
            or_clauses = map(NotOperator, self.clauses - set(not_clauses))
            # and remove the negation from the negated ones
            not_clauses = map(lambda x: iter(x.clauses).next(), not_clauses)
            # then and the result
            return NotOperator(AndOperator(or_clauses + not_clauses)).render()
        else:
            rv = ['(']
            rv.append(' UNION '.join(map(lambda x: x.render(), self.clauses)))
            rv.append(')')
            return ' '.join(rv)

class NotOperator(Operator):
    """We can't actually render a not operator without implicitly
    ANDing it with the entire database.  For now, we just raise an
    exception.  Nots are actually implemented in "and" using the
    EXCEPT sql operator.
    """
    def __str__(self):
        return "~(" + str(iter(self.clauses).next()) + ')'

    def render(self):
        raise QueryException()

def normalize(stmt):
    """Apply demorgans rule to the query.
    """
    if hasattr(stmt, 'check_not'):
        newstmt = stmt.check_not()
    else:
        newstmt = stmt
    return newstmt

if __name__ == '__main__':
    ast = AndOperator([Clause('c2'), OrOperator([Clause('c1'), NotOperator(Clause('c3'))])])
    print ast
    print normalize(ast).render()

