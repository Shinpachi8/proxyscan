#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from lib.common import *
from config import *
# from URLPollution.urlpollution import Pollution
import urlparse
import re
import itertools
import random
import difflib
import urllib
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

#FUZZY_THRESHOLD = 0.95
#DIFF_TOLERANCE = 0.05
RANDINT = random.randint(1, 255)
LOWER_RATIO_BOUND = 0.02
UPPER_RATIO_BOUND = 0.98
responseTimes = []

def check(url, method, data, headers):
    return True

def html_encode(payload):
    payloads = [payload]
    html_code = {
                    ' ':[' ', '&nbsp;'],#&#160;
                    '>':['&gt;', '&#62;'],
                    '"':['&quot;', '&#34;'],
                    "'":['&apos;', '&#39;'],
                }
    for chars in html_code:
        tmp_payloads = payloads[:]
        payloads = []
        for char in html_code[chars]:
            for payload in tmp_payloads:
                _ = payload.replace(chars, char)
                payloads.append(_)
    return payloads
def get_all_encode(payload):
    payloads = []
    payloads.append(payload) #原生
    payloads.append(urllib.quote(payload)) #URL编码
    payloads.extend(html_encode(payload)) #HTML实体编码组合
    return list(set(payloads))

def parse_html(html, payload=None, origin=False):
    if not origin:
        res = get_all_encode(payload)
        for s in res:
            html = re.sub(r"(?i)%s" % re.escape(s), "", html)
    match = re.search(r"<title>(?P<result>[^<]+)</title>", html, re.I)
    title = match.group("result") if match and "result" in match.groupdict() else None
    #text = re.sub(r"(?si)<script.+?</script>|<!--.+?-->|<style.+?</style>|<[^>]+>|\s+", " ", html)
    text = re.sub(r"(?si)<script.+?</script>|<!--.+?-->|<style.+?</style>", " ", html)
    return html, title, text

def check_ratio(max_r, min_r):
    if max_r > UPPER_RATIO_BOUND and min_r < LOWER_RATIO_BOUND:
        return True
    elif max_r > UPPER_RATIO_BOUND and (LOWER_RATIO_BOUND <= min_r <= UPPER_RATIO_BOUND):
        return abs(max_r - min_r) > 0.1
    elif min_r < LOWER_RATIO_BOUND and (LOWER_RATIO_BOUND <= max_r <= UPPER_RATIO_BOUND):
        return abs(max_r - min_r) > 0.3
    elif (LOWER_RATIO_BOUND <= min_r <= UPPER_RATIO_BOUND) and (LOWER_RATIO_BOUND <= max_r <= UPPER_RATIO_BOUND):
        return abs(max_r - min_r) > 0.3
    else:
        return False

def check_vul(ocode, ohtml, tcode, thtml, fcode, fhtml, tpayload, fpayload):
    ohtml, otitle, otext = parse_html(ohtml, origin=True)
    thtml, ttitle, ttext = parse_html(thtml, tpayload)
    fhtml, ftitle, ftext = parse_html(fhtml, fpayload)
    vulnerable = False
    if all(code != -1 for code in (ocode, tcode, fcode)) and ttext != ftext:
        if (ocode == tcode != fcode) or (otitle == ttitle != ftitle):
            #vulnerable = True
            vulnerable = 'ocode:{0} tcode:{1} fcode:{2}\n\notitle:{3} ttitle:{4} ftitle:{5}'.format(ocode, tcode, fcode, otitle, ttitle, ftitle)
        else:
            text = {False: ftext, True: ttext}
            ratios = dict((_, difflib.SequenceMatcher(None, otext, text[_]).quick_ratio()) for _ in (False, True))
            #vulnerable = min(ratios.values()) < FUZZY_THRESHOLD < max(ratios.values()) and abs(ratios[True] - ratios[False]) > FUZZY_THRESHOLD / 10
            if check_ratio(max(ratios.values()), min(ratios.values())):
                print max(ratios.values()), min(ratios.values())
                #vulnerable = True
                vulnerable = 'max:{0} min:{1}'.format(max(ratios.values()), min(ratios.values()))
    return vulnerable
def get_payloads(RANDINT):
    results = []
    payloads = sqli_bool_payloads()
    for template in payloads:
        if '%s' == template:
            payload = dict((_, (template % ('-188*122*0' if _ else '-188*122*1'))) for _ in (True, False))
        else:
            payload = dict((_, (template % (RANDINT if _ else RANDINT + 1, RANDINT))) for _ in (True, False))
        results.append(payload)
    return results
def cookie_payload(cookie, payload):
    cookies = []
    filters = []
    cookie = cookie.replace('&','%26')
    for line in cookie.split(';'):
        line = line.split('=')
        if len(line) == 2:
            key = line[0].strip()
            value = line[1].strip()
            _ = key + '=' + value
            if cookie_filter(key):
                cookies.append(_)
            else:
                filters.append(_)
    cookie = '&'.join(cookies)
    # datas = Pollution([payload]).payload_generator(cookie, append=True)
    datas = Pollution(cookie, [payload,], replace=False).payload_generate()
    datas = [urllib.urlencode(data) for data in datas]
    results = []
    for data in datas:
        _ = data.split('&')
        _.extend(filters)
        _ = ';'.join(_)
        results.append(_)
    return results

def _http_request_get(url, headers):
    code, head, html, time = http_request_get(url, headers=headers, time_check=True)
    if code != -1:
        responseTimes.append(time)
    return code, head, html
def _http_request_post(url, data, headers):
    code, head, html, time = http_request_post(url, data, headers=headers, time_check=True)
    if code != -1:
        responseTimes.append(time)
    return code, head, html

def run(url, method, data, headers, proxy_headers=None):
    try:
        VUL = False
        # host = urlparse.urlparse(url).netloc
        parsed_url = urlparse.urlparse(url)
        host = parsed_url.netloc
        query = parsed_url.query

        url = url.encode('utf-8')
        if data is not None:
            data = data.encode('utf-8')
        else:
            data = ''
        headers = get_headers(url, method, data, headers, proxy_headers)
        payloads = get_payloads(RANDINT)
        headers_fuzz = {'Host':host,
                        'Referer':headers.get('Referer',''),
                        'User-Agent':headers.get('User-Agent',''),
                        'X-Forwarded-Host':'localhost',
                        'X-Forwarded-For':'127.0.0.1',
                        'X-Real-IP':'127.0.0.1',
                        'Client-IP':'127.0.0.1',
                       }
        # print headers_fuzz
        #====================================================================================
        if method == 'GET':
            ocode, ohead, ohtml = http_request_get(url, headers=headers)
            # print ocode, ohead, ohtml
            for payload in payloads:
                tpayload = payload[True]
                fpayload = payload[False]
        #====================================================================================
                # turls = Pollution([tpayload]).payload_generator(url, append=True)
                # furls = Pollution([fpayload]).payload_generator(url, append=True)
                query_dicts = Pollution(query, [tpayload,], replace=False).payload_generate()
                turls = []
                for d in query_dicts:
                    u = urlparse.urlunparse((parsed_url.scheme, parsed_url.netloc,parsed_url.path,'',urllib.urlencode(d), parsed_url.fragment))
                    turls.append(u)

                query_dicts = Pollution(query, [fpayload,], replace=False).payload_generate()
                furls = []
                for d in query_dicts:
                    u = urlparse.urlunparse((parsed_url.scheme, parsed_url.netloc,parsed_url.path,'',urllib.urlencode(d), parsed_url.fragment))
                    furls.append(u)

                print turls, furls
                for index in range(len(turls)):
                    fcode, fhead, fhtml = _http_request_get(furls[index], headers=headers)
                    tcode, thead, thtml = _http_request_get(turls[index], headers=headers)
                    flag = check_vul(ocode, ohtml, tcode, thtml, fcode, fhtml, tpayload, fpayload)
                    print flag
                    if flag:
                        VUL = turls[index] + '\n\n' + flag
                        break
                if VUL:
                    return {'target':host, 'type':'Sqli Bool Injection', 'info':VUL}
        #====================================================================================
                cookies = headers.get('Cookie','')
                tcookies = cookie_payload(cookies, tpayload)
                fcookies = cookie_payload(cookies, fpayload)
                for index in range(len(tcookies)):
                    tmp_headers = dict(headers)
                    tmp_headers['Cookie'] = fcookies[index]
                    fcode, fhead, fhtml = _http_request_get(url, headers=tmp_headers)
                    tmp_headers = dict(headers)
                    tmp_headers['Cookie'] = tcookies[index]
                    tcode, thead, thtml = _http_request_get(url, headers=tmp_headers)
                    flag = check_vul(ocode, ohtml, tcode, thtml, fcode, fhtml, tpayload, fpayload)
                    if flag:
                        VUL = '{0}\n\n{1}: {2}'.format(url, 'Cookie', tmp_headers['Cookie']) + '\n\n' + flag
                        break
                if VUL:
                    return {'target':host, 'type':'Sqli Bool Injection', 'info':VUL}
        #====================================================================================
                for h in headers_fuzz:
                    tmp_headers = dict(headers)
                    tmp_headers[h] = headers_fuzz[h] + fpayload
                    fcode, fhead, fhtml = _http_request_get(url, headers=tmp_headers)

                    tmp_headers = dict(headers)
                    tmp_headers[h] = headers_fuzz[h] + tpayload
                    tcode, thead, thtml = _http_request_get(url, headers=tmp_headers)
                    flag = check_vul(ocode, ohtml, tcode, thtml, fcode, fhtml, tpayload, fpayload)
                    if flag:
                        VUL = '{0}\n\n{1}: {2}'.format(url, h, tmp_headers[h]) + '\n\n' + flag
                        break
                if VUL:
                    return {'target':host, 'type':'Sqli Bool Injection', 'info':VUL}
        #====================================================================================
        else:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            ocode, ohead, ohtml = http_request_post(url, data, headers=headers)
            for payload in payloads:
                tpayload = payload[True]
                fpayload = payload[False]
        #====================================================================================
                # turls = Pollution([tpayload]).payload_generator(url, append=True)
                # furls = Pollution([fpayload]).payload_generator(url, append=True)
                query_dicts = Pollution(query, [tpayload,], replace=False).payload_generate()
                turls = []
                for d in query_dicts:
                    u = urlparse.urlunparse((parsed_url.scheme, parsed_url.netloc,parsed_url.path,'',urllib.urlencode(d), parsed_url.fragment))
                    turls.append(u)

                query_dicts = Pollution(query, [fpayload,], replace=False).payload_generate()
                furls = []
                for d in query_dicts:
                    u = urlparse.urlunparse((parsed_url.scheme, parsed_url.netloc,parsed_url.path,'',urllib.urlencode(d), parsed_url.fragment))
                    furls.append(u)

                for index in range(len(turls)):
                    fcode, fhead, fhtml = _http_request_post(furls[index], data, headers=headers)
                    tcode, thead, thtml = _http_request_post(turls[index], data, headers=headers)
                    flag = check_vul(ocode, ohtml, tcode, thtml, fcode, fhtml)
                    if flag:
                        VUL = turls[index] + '\n\n' + data + '\n\n' + flag
                        break
                if not VUL:
                    # tdatas = Pollution([tpayload]).payload_generator(data, append=True)
                    # fdatas = Pollution([fpayload]).payload_generator(data, append=True)
                    tdatas = Pollution(query, [tpayload,], replace=False).payload_generate()
                    # turls = []
                    # for d in query_dicts:
                    #     u = urlparse.urlunparse((parsed_url.scheme, parsed_url.netloc,parsed_url.path,'',urllib.urlencode(d), parsed_url.fragment))
                    #     turls.append(u)

                    fdatas = Pollution(query, [fpayload,], replace=False).payload_generate()
                    # furls = []
                    # for d in query_dicts:
                    #     u = urlparse.urlunparse((parsed_url.scheme, parsed_url.netloc,parsed_url.path,'',urllib.urlencode(d), parsed_url.fragment))
                    #     furls.append(u)
                    for index in range(len(tdatas)):
                        fcode, fhead, fhtml = _http_request_post(url, fdatas[index], headers=headers)
                        tcode, thead, thtml = _http_request_post(url, tdatas[index], headers=headers)
                        flag =  check_vul(ocode, ohtml, tcode, thtml, fcode, fhtml)
                        if flag:
                            VUL = url + '\n\n' + tdatas[index] + '\n\n' + flag
                            break
                if VUL:
                    return {'target':host, 'type':'Sqli Bool Injection', 'info':VUL}
        #====================================================================================
                cookies = headers.get('Cookie','')
                tcookies = cookie_payload(cookies, tpayload)
                fcookies = cookie_payload(cookies, fpayload)
                for index in range(len(tcookies)):
                    tmp_headers = dict(headers)
                    tmp_headers['Cookie'] = fcookies[index]
                    fcode, fhead, fhtml = _http_request_post(url, data, headers=tmp_headers)
                    tmp_headers = dict(headers)
                    tmp_headers['Cookie'] = tcookies[index]
                    tcode, thead, thtml = _http_request_post(url, data, headers=tmp_headers)
                    flag = check_vul(ocode, ohtml, tcode, thtml, fcode, fhtml)
                    if flag:
                        VUL = '{0}\n\n{1}\n\n{2}: {3}'.format(url, data, 'Cookie', tmp_headers['Cookie']) + '\n\n' + flag
                        break
                if VUL:
                    return {'target':host, 'type':'Sqli Bool Injection', 'info':VUL}
        #====================================================================================
                for h in headers_fuzz:
                    tmp_headers = dict(headers)
                    tmp_headers[h] = headers_fuzz[h] + fpayload
                    fcode, fhead, fhtml = _http_request_post(url, data, headers=tmp_headers)

                    tmp_headers = dict(headers)
                    tmp_headers[h] = headers_fuzz[h] + fpayload
                    tcode, thead, thtml = _http_request_post(url, data, headers=tmp_headers)
                    flag = check_vul(ocode, ohtml, tcode, thtml, fcode, fhtml)
                    if flag:
                        VUL = '{0}\n\n{1}\n\n{2}: {3}'.format(url, data, h, tmp_headers[h]) + '\n\n' + flag
                        break
                if VUL:
                    return {'target':host, 'type':'Sqli Bool Injection', 'info':VUL}
        #====================================================================================
    except Exception, e:
        print repr(e)
        pass
#print run('http://testphp.vulnweb.com/artists.php?artist=1','GET','',{'cookie':''})
#print run('http://127.0.0.1/sqli.php?id=1','GET','',{'cookie':''})
def verify(task):

    message = {
        "method": "",
        "url" : "",
        "param" : "",
        "type" : "sqli-bool",
        "info" : "[sqli bool]",
    }
    url = task['url']
    method = task['method']
    headers = task['request_header']
    data = task['request_content'] if method == 'POST' else None


    result = run(url, method, data, headers)
    if result:
        message['method'] = method
        message['url'] = url
        message['param'] = result['info']
        save_to_databases(message)
        result = (True, message)
    else:
        result = (False, {})

    return result
if __name__ == '__main__':
    task = {
        'url': 'http://127.0.0.1:8000/vulnerabilities/sqli_blind/?id=1&Submit=Submit#',
        'request_header': {
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-GB,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Referer': 'http://127.0.0.1:8000/vulnerabilities/exec/',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Cookie': 'sessions=%7B%7D; csrftoken=71w812VAMB8nvVNcYgOmwW6ftN8igDyZsqE9FHz2MsGdQpgdmwpl1jzG2iE7YwLZ; sessionid=x4phtuh6qv5zhpcu46v1xlszto8pbib1; PHPSESSID=ktd1uec9ekucj6afr284i5bks6; security=low; hibext_instdsigdipv2=1; GUID=LgyzlhQfEaDsb0uiyhiN',
        },
        'request_content': '',
        'method': 'GET'
    }
    print verify(task)
