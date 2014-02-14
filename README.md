qualysguard_was_export_csv
==========================

Generate CSV from webapps that were recently scanned by QualysGuard WAS.

Description
===========

Script is intended to run via cron job to pip out CSV file that is being watched by a GRC tool.

The CSV contains the data points in the following order:

    webapp name, vuln ID, vuln QID, severity, cwe, vuln_title, vuln STATUS, vuln URL, vuln FIRST_TIME_DETECTED, vuln LAST_TIME_DETECTED, vuln IGNORED

CSV format:
 * Quoted with double-quotes (") characters against all fields.
 * Comma (,) delimiter
 * Unicode characters stripped out, and converted if possible ('ā' becomes 'a').

Usage
=====

    usage: qualysguard_was_export_csv.py [-h] [-a OVERRIDE_ALL_APPS]
                                         [-D OVERRIDE_DATE] [-d DAYS]
                                         [-o OUTPUT_FILENAME] [-r RESUME] [-t TAG]
                                         [-v] [--config CONFIG]
    
    Generate CSV from webapps that were recently scanned by QualysGuard WAS.
    
    optional arguments:
      -h, --help            show this help message and exit
      -a OVERRIDE_ALL_APPS, --override_all_apps OVERRIDE_ALL_APPS
                            Generate report for all webapps. Automatically
                            selected for first run.
      -D OVERRIDE_DATE, --override_date OVERRIDE_DATE
                            Search scans from DATE_OVERRIDE date (YYYY-MM-DD).
      -d DAYS, --days DAYS  Search scans back DAYS day(s) from today midnight.
      -o OUTPUT_FILENAME, --output_filename OUTPUT_FILENAME
                            Filename of outputted CSV. (Default =
                            qualysguard_was.csv)
      -r RESUME, --resume RESUME
                            Search scans ahead RESUME days from last previous
                            successfully imported date.
      -t TAG, --tag TAG     Scope import to webapps with TAG tag. Overrides
                            OVERRIDE_ALL_APPS.
      -v, --verbose         Outputs additional information to log.
      --config CONFIG       Configuration for Qualys connector.

Sample output
=============

    "Webapp 1","1146815","150000","5","CWE-79","Persistent Cross-Site Scripting (XSS) Vulnerabilities","FIXED","http://webapp1.com/?s=javascript%3Aqxss%28x149748204y1z%29%3B&feed=rss2","2013-06-19T13:17:30Z","2013-06-22T10:00:33Z","FALSE"
    "Webapp 1","521005","150001","5","CWE-79","Reflected Cross-Site Scripting (XSS) Vulnerabilities","FIXED","http://webapp1.com/?paged=%22'%3E%3Cqss%20a%3DX168954180Y1Z%3E","2012-07-28T09:57:01Z","2012-07-28T09:57:01Z","FALSE"
    "Webapp 1","860639","150001","5","CWE-79","Reflected Cross-Site Scripting (XSS) Vulnerabilities","FIXED","http://webapp1.com/?m=%22'%3E%3Cqss%20a%3DX3001098420Y1Z%3E&paged=2","2013-02-20T14:01:30Z","2013-02-20T14:01:30Z","FALSE"
    "Webapp 1","1316759","150001","5","CWE-79","Reflected Cross-Site Scripting (XSS) Vulnerabilities","FIXED","https://webapp1.com/?s=%22%20onEvent%3DX3042404348Y1Z%20","2013-08-07T21:05:01Z","2013-08-07T21:05:01Z","FALSE"
    "Webapp 1","626492","150084","1","CWE-79","Unencoded characters ","FIXED","https://webapp1.com/wp-login.php?redirect_to=%22'%3E%3C%3CSCRIPT%20a%3D2%3Eqss%3D7%3B%2F%2F%3C%3C%2FSCRIPT%3E&reauth=1","2012-09-29T09:55:31Z","2013-01-05T10:55:05Z","FALSE"
    "Webapp 1","1054949","150084","1","CWE-79","Unencoded characters ","FIXED","http://webapp1.com/?author=%22'%3E%3C%3CSCRIPT%20a%3D2%3Eqss%3D7%3B%2F%2F%3C%3C%2FSCRIPT%3E&paged=2","2013-05-15T18:27:33Z","2013-09-18T13:19:32Z","FALSE"
    "Webapp 1","2025505","150084","1","CWE-79","Unencoded characters ","FIXED","http://webapp1.com/?s=1234%27+or+%27w%27%3D%27w","2014-01-29T14:00:46Z","2014-01-29T14:00:46Z","FALSE"
    "Webapp 1","520989","150001","5","CWE-79","Reflected Cross-Site Scripting (XSS) Vulnerabilities","FIXED","http://webapp1.com/?s=%22+onevent=x3074671764y1z');waitfor+delay+'00:00:59'--","2012-07-28T09:57:01Z","2013-01-16T13:05:30Z","FALSE"
    "Webapp 1","1015526","150000","5","CWE-79","Persistent Cross-Site Scripting (XSS) Vulnerabilities","FIXED","http://webapp1.com/?s=1e3091+or+4%3D5","2013-04-24T13:16:30Z","2013-04-24T13:16:30Z","FALSE"
    "Webapp 2","2090836","150071","3","CWE-352","Form Can Be Manipulated with Cross-Site Request Forgery (CSRF) ","NEW","http://webapp2.net/188150784029/newsnippet.gtl","2014-02-13T20:45:54Z","2014-02-13T20:45:54Z","FALSE"
    "Webapp 2","210314","150001","5","CWE-79","Reflected Cross-Site Scripting (XSS) Vulnerabilities","FIXED","http://webapp2.net/188150784029/snippets.gtl?uid='%20onEvent%3dX155784108Y1Z%20","2012-02-16T04:16:01Z","2012-02-16T04:16:01Z","FALSE"
    "Webapp 2","751689","150084","1","CWE-79","Unencoded characters ","ACTIVE","http://webapp2.net/188150784029/login?uid=%22'%3E%3C%3CSCRIPT%20a%3D2%3Eqss%3D7%3B%2F%2F%3C%3C%2FSCRIPT%3E&pw=password","2012-12-07T17:20:46Z","2014-02-13T20:45:54Z","FALSE"
    "Webapp 2","210320","150001","5","CWE-79","Reflected Cross-Site Scripting (XSS) Vulnerabilities","FIXED","http://webapp2.net/188150784029/feed.gtl?uid=%22'%3e%3cqss%20a%3dX139433740Y1Z%3e","2012-02-16T04:54:16Z","2012-02-16T04:54:16Z","FALSE"
    "Webapp 2","205794","150084","1","CWE-79","Unencoded characters ","NEW","http://webapp2.net/188150784029/snippets.gtl?uid=%22%20onEvent%3dX162137012Y1Z%20","2012-02-10T17:51:49Z","2012-02-10T17:51:49Z","FALSE"
    "Webapp 3","1423623","150001","5","CWE-79","Reflected Cross-Site Scripting (XSS) Vulnerabilities","FIXED","http://webapp2.net/174524148849/snippets.gtl?uid='%20onEvent%3DX154537288Y1Z%20","2013-09-13T16:02:00Z","2013-09-13T16:02:00Z","FALSE"
    "Webapp 3","705522","150081","1","","Possible Clickjacking Vulnerability","FIXED","http://webapp2.net/174524148849/newsnippet.gtl","2012-11-09T16:12:00Z","2013-08-30T16:03:01Z","FALSE"
