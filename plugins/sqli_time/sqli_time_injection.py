#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from common import *
from URLPollution.urlpollution import Pollution
from math import sqrt
import urlparse
import re
import sys
import urllib
import json
import traceback
reload(sys)
sys.setdefaultencoding('utf-8')

TIMESLEEP = 3
MIN_VALID_DELAYED_RESPONSE = 2
TIMEOUT = 60

def check(url, method, data, headers):
    return True

def get_payloads():
    payloads = sqli_time_payloads()
    return payloads

#标准差
def stdev(values):
    if not values or len(values) < 2:
        return None
    key = (values[0], values[-1], len(values))
    avg = average(values)
    _ = reduce(lambda x, y: x + pow((y or 0) - avg, 2), values, 0.0)
    retVal = sqrt(_ / (len(values) - 1))
    return retVal

#平均值
def average(values):
    return (sum(values) / len(values)) if values else None

#30次正常请求时间集
def get_request_time(url, headers, responseTimes=None):
    if responseTimes == None:
        responseTimes = []
    count = 0
    while len(responseTimes) < 30:
        #print len(responseTimes)
        code, head, html, time = http_request_get(url, headers=headers, timeout=TIMEOUT, time_check=True)
        if code != -1:
            responseTimes.append(time)
        else:
            count = count + 1
        if count > 10:
            return 0
    time = average(responseTimes) + stdev(responseTimes)*7
    print time
    return time

#COOKIE参数污染
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
    datas = Pollution([payload]).payload_generator(cookie, append=True)
    results = []
    for data in datas:
        _ = data.split('&')
        _.extend(filters)
        _ = ';'.join(_)
        results.append(_)
    return results

#伪静态参数污染
def rewrite_payload(url, payload):
    urls = []
    payload = urllib.quote(payload)
    url = url.split('XXXREWRITEXXX')
    for index in range(len(url)-1):
        tmp = list(url)
        tmp[index] += payload
        urls.append(''.join(tmp))
    return urls

#伪静态标记
def rewrite(url, payload):
    ascii = ' !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~'
    flags = ['/', '_', '-', ',', '&', '=', '!', '.']
    r = '(\\' + '|\\'.join(flags) + ')'
    ori_path = urlparse.urlparse(url).path
    new_path = ''
    if re.match(r"(?i)/(.+)\.(html|htm|xhtml|xhtm|shtml|shtm)$",ori_path):
        extion = ori_path[ori_path.rfind('.'):]
    else:
        extion = ''
    paths = re.split(r, ori_path.replace(extion,''))
    for _path in paths:
        if _path and _path not in flags:
            if _path.isdigit():
                #数字
                new_path += _path + 'XXXREWRITEXXX'
            else:
                for Str in urllib.unquote(_path):
                    if Str not in ascii:
                        #非英文
                        new_path += _path
                        break
                else:
                    #英文
                    new_path += _path
                    pass
        else:
            new_path += _path
    return rewrite_payload(url.replace(ori_path, new_path+extion), payload)

def json_payload(data, payload):
    try:
        #payload = urllib.quote(payload)
        payload = payload.replace('"', '\\"')
        data = json.loads(data)
        datas = []
        for key in data:
            temp = dict(data)
            try:
                temp[key] = str(temp[key]) + 'JSONPAYLOAD'
            except:
                temp[key] = temp[key] + 'JSONPAYLOAD'
            _ = json.dumps(temp, ensure_ascii=False).encode('utf-8')
            datas.append(_.replace('JSONPAYLOAD',payload))
        return datas
    except:
        return []

def replace_payload(method, url, headers, SLEEP_TIME, data=None):
    url = url.replace('XXXTIMESLEEPXXX', SLEEP_TIME)
    _headers = dict(headers)
    for key in _headers:
        _headers[key] = _headers[key].replace('XXXTIMESLEEPXXX', SLEEP_TIME)
    if method == 'GET':
        return url, _headers
    else:
        data = data.replace('XXXTIMESLEEPXXX', SLEEP_TIME)
        return url, _headers, data

def check_vul(method, SLEEP_TIME, url, headers, data=None):
    truetime = str(int(SLEEP_TIME) + TIMESLEEP)
    falsetime = '0'
    TRUE_TIME = max(MIN_VALID_DELAYED_RESPONSE, SLEEP_TIME)
    #FALSE_TIME = SLEEP_TIME
    if method == 'GET':
        url_1, headers_1 = replace_payload(method, url, headers, truetime)
        url_2, headers_2 = replace_payload(method, url, headers, falsetime)
        code, head, html, time = http_request_get(url_1, headers=headers_1, timeout=TIMEOUT, time_check=True)
        if time > TRUE_TIME:
            code, head, html, time = http_request_get(url_2, headers=headers_2, timeout=TIMEOUT, time_check=True)
            if time > TRUE_TIME:
                return
            code, head, html, time = http_request_get(url_1, headers=headers_1, timeout=TIMEOUT, time_check=True)
            if time > TRUE_TIME:
                return time
    else:
        url_1, headers_1, data_1 = replace_payload(method, url, headers, truetime, data)
        url_2, headers_2, data_2 = replace_payload(method, url, headers, falsetime, data)
        code, head, html, time = http_request_post(url_1, data_1, headers=headers_1, timeout=TIMEOUT, time_check=True)
        if time > TRUE_TIME:
            code, head, html, time = http_request_post(url_2, data_2, headers=headers_2, timeout=TIMEOUT, time_check=True)
            if time > TRUE_TIME:
                return
            code, head, html, time = http_request_post(url_1, data_1, headers=headers_1, timeout=TIMEOUT, time_check=True)
            if time > TRUE_TIME:
                return time

def run(url, method, data, headers, proxy_headers=None, responseTimes=None):
    try:
        url = url.encode('utf-8')
        data = data.encode('utf-8')

        host = urlparse.urlparse(url).netloc
        query = urlparse.urlparse(url).query
        regex = re.match(r"(?i)(http|https)://[^\?]+\.(php|asp|aspx|jsp|jspx|do|action|xml|ashx|cgi|sh|pl)$",url.split('#')[0])

        headers = get_headers(url, method, data, headers, proxy_headers)
        headers_fuzz = {'Host':host,
                        'Referer':headers.get('Referer',''),
                        'User-Agent':headers.get('User-Agent',''),
                        'X-Forwarded-Host':'localhost',
                        'X-Forwarded-For':'127.0.0.1',
                        'X-Real-IP':'127.0.0.1',
                        'Client-IP':'127.0.0.1',
                       }

        payloads = get_payloads()
        SLEEP_TIME = get_request_time(url, headers, responseTimes)
        if SLEEP_TIME == 0:
            return
        #====================================================================================
        if method == 'GET':
            for payload in payloads:
        #伪静态==============================================================================
                if query == '' and not regex:
                    urls = rewrite(url, payload)
                    for _url in urls:
                        time = check_vul('GET', SLEEP_TIME, _url, headers)
                        if time:
                            info = '{0}\n\n{1}'.format(_url, str(time) + '>' + str(SLEEP_TIME))
                            return {'target':host, 'type':'Sqli Time Injection', 'info':info}
        #GET=================================================================================
                urls = Pollution([payload]).payload_generator(url, append=True)
                for _url in urls:
                    time = check_vul('GET', SLEEP_TIME, _url, headers)
                    if time:
                        info = '{0}\n\n{1}'.format(_url, str(time) + '>' + str(SLEEP_TIME))
                        return {'target':host, 'type':'Sqli Time Injection', 'info':info}
        #COOKIE==============================================================================
                cookies = cookie_payload(headers.get('Cookie',''), payload)
                for _cookie in cookies:
                    tmp_headers = dict(headers)
                    tmp_headers['Cookie'] = _cookie
                    time = check_vul('GET', SLEEP_TIME, url, tmp_headers)
                    if time:
                        info = '{0}\n\n{1}: {2}\n\n{3}'.format(url, 'Cookie', tmp_headers['Cookie'], str(time) + '>' + str(SLEEP_TIME))
                        return {'target':host, 'type':'Sqli Time Injection', 'info':info}
        #Headers----=========================================================================
                for h in headers_fuzz:
                    tmp_headers = dict(headers)
                    tmp_headers[h] = headers_fuzz[h] + payload
                    time = check_vul('GET', SLEEP_TIME, url, tmp_headers)
                    if time:
                        info = '{0}\n\n{1}: {2}\n\n{3}'.format(url, h, tmp_headers[h], str(time) + '>' + str(SLEEP_TIME))
                        return {'target':host, 'type':'Sqli Time Injection', 'info':info}
        #====================================================================================
        else:
            is_json = re.match(r"{(.+):(.+)}$",data.strip())
            #is_xml
            #is_mul
            if 'Content-Type' not in headers:
                if is_json:
                    headers['Content-Type'] = 'application/json'
                #elif xml
                #elif multipart
                else:
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
            for payload in payloads:
        #GET=================================================================================
                urls = Pollution([payload]).payload_generator(url, append=True)
                for _url in urls:
                    time = check_vul('POST', SLEEP_TIME, _url, headers, data)
                    if time:
                        info = '{0}\n\n{1}\n\n{2}'.format(_url, data, str(time) + '>' + str(SLEEP_TIME))
                        return {'target':host, 'type':'Sqli Time Injection', 'info':info}
        #JSON================================================================================
                if is_json:
                    datas = json_payload(data.strip(), payload)
                    for _data in datas:
                        time = check_vul('POST', SLEEP_TIME, url, headers, _data)
                        if time:
                            info = '{0}\n\n{1}\n\n{2}'.format(url, _data, str(time) + '>' + str(SLEEP_TIME))
                            return {'target':host, 'type':'Sqli Time Injection', 'info':info}
        #POST================================================================================
                else:
                    datas = Pollution([payload]).payload_generator(data, append=True)
                    for _data in datas:
                        time = check_vul('POST', SLEEP_TIME, url, headers, _data)
                        if time:
                            info = '{0}\n\n{1}\n\n{2}'.format(url, _data, str(time) + '>' + str(SLEEP_TIME))
                            return {'target':host, 'type':'Sqli Time Injection', 'info':info}
        #COOKIE==============================================================================
                cookies = cookie_payload(headers.get('Cookie',''), payload)
                for _cookie in cookies:
                    tmp_headers = dict(headers)
                    tmp_headers['Cookie'] = _cookie
                    time = check_vul('GET', SLEEP_TIME, url, tmp_headers, data)
                    if time:
                        info = '{0}\n\n{1}\n\n{2}: {3}\n\n{4}'.format(url, data, 'Cookie', tmp_headers['Cookie'], str(time) + '>' + str(SLEEP_TIME))
                        return {'target':host, 'type':'Sqli Time Injection', 'info':info}
        #Headers=============================================================================
                for h in headers_fuzz:
                    tmp_headers = dict(headers)
                    tmp_headers[h] = headers_fuzz[h] + payload
                    time = check_vul('GET', SLEEP_TIME, url, tmp_headers)
                    if time:
                        info = '{0}\n\n{1}\n\n{2}: {3}\n\n{4}'.format(url, data, h, tmp_headers[h], str(time) + '>' + str(SLEEP_TIME))
                        return {'target':host, 'type':'Sqli Time Injection', 'info':info}
        #====================================================================================
    except Exception, e:
        #print traceback.format_exc()
        pass
# print run('http://127.0.0.1/sqli-labs/Less-32/?id=1','GET','', {'cookie':'id=1;s=s;'})
# print run('http://127.0.0.1/sqli-labs/Less-33/?id=1','GET','', {'cookie':'id=1;s=s;'})
