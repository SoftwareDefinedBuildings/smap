
import re
import sys

headers = [('^=([^=].*[^=])=$', '-'),
           ('^==([^=].*[^=])==$', '~'),
           ('^===([^=].*[^=])===$', '"')]

def convert_headers(line):
    for (pat, char) in headers:
        # process section headers
        m = re.match(pat, line.strip())
        if m:
            h = m.groups(1)[0].strip()
            print h
            print char * len(h)
            print
            return True
    return False

def convert_emph(line):
    line = line.replace('`', '``')
    line = line.replace('*', '**')
    # fix lists
    if line.startswith('**') and line.count('**', 2) % 2 == 0:
        line = '*' + line[2:]
    return line

def convert_code(line):
    if line.startswith('{{{'):
        print
        print ".. code-block:: python"
        print
        while True:
            line = sys.stdin.readline()
            if line.startswith('}}}'): return True
            else: print "  " + line.strip()
    return False

def convert_table(line):
    rows = []
    # remove header formatting
    line = line.replace('*', '')
    while True:
        if line.startswith('||'):
            rows.append(re.split('\|\|', line.strip()))
        else:
            break
        line = sys.stdin.readline()
        if not line: break

    if len(rows):
        row_lengths = [0] * len(rows[0])
        for r in rows:
            row_lengths = map(max, zip(row_lengths, map(len, r)))
        if row_lengths[-1] != 0:
            row_lengths.append(0)

        def make_row(row):
            return '|'.join(map(lambda (x, y): x + (' ' * (y - len(x))), 
                                zip(row, row_lengths)))

        sep = '+'.join(map(lambda x: '-' * x, row_lengths))
        print
        print sep
        print make_row(rows[0])
        print '+'.join(map(lambda x: '=' * x, row_lengths))
        for r in rows[1:]:
            print make_row(r)
            print sep
        print


    

    return len(rows) > 0


while True:
    line = sys.stdin.readline()
    if not line: break

    if convert_headers(line): continue
    if convert_code(line): continue
    if convert_table(line): continue
    else: print convert_emph(line.strip())
    
