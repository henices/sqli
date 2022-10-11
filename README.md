# SQLi Scanner

Small and full functional sql injection detection.

```
small SQLi Scanner #v1.0
 by: zz@nsfocus

Usage: sqli.py [options]

Options:
  --version            show program's version number and exit
  -h, --help           show this help message and exit
  -u URL, --url=URL    Target URL (e.g. "http://www.target.com/page.htm?id=1")
  --data=DATA          POST data (e.g. "query=test")
  --cookie=COOKIE      HTTP Cookie header value
  --user-agent=UA      HTTP User-Agent header value
  --referer=REFERER    HTTP Referer header value
  --proxy=PROXY        HTTP proxy address (e.g. "http://127.0.0.1:8080")
  --classify=CLASSIFY  SQLi technique, valule: EBTSU (e.g. --technique=U),
                       default is all
  -v VERBOSE           Verbosity level, 0-2, default is 0
  -s SKILL             Bypass filter, 1-n (1. /**/), default is None
```

## Thanks

- https://github.com/stamparm/DSSS
- https://github.com/sqlmapproject/sqlmap

