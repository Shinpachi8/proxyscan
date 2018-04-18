#!/usr/bin/env python
# -*-coding:utf-8 -*-

# SERVER SIDE TEMPLATE INJECTION


import requests
import Queue
import urlparse
import time
import copy
from config import *
from lib.common import *



def verify(task):
    """
    this function aim to detect the server side template injection
    :param: task, the proxy request item
    {
        "method" : "GET",
        "url" : "http://api.t.iqiyi.com/feed/get_feed?uid=1409979958&authcookie=44zpCeNFgez79OVwz7GjJWVUaTN2m1bHxsQNLm306MVZm2m3ruh4Qm2w4SYwqDT9sDTos148d&device_id=mqaguvg2qatzipbhxzd2sbcxadxumaaz&agenttype=121&agentversion=6.0.46.4598&wallId=false&feedId=30267718948&version=1&praise=0&callback=jQuery17206312791961245239_1502178651908&_=1502178652025",
        "request_header" : {"Accept-Language": "en-US,en;q=0.8", "Accept-Encoding": "identity", "Accept": "*/*", "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36 Falcon/5.0.7.1", "Host": "api.t.iqiyi.com", "Referer": "http://paopaoquan.iqiyi.com/feed", "Cookie": "P00004=-898887952.1501743222.891ba158bb; QC008=1498535221.1501744345.1501744345.3; QC005=437b5f59bacf7103319dfd55207aba05; P00001=08ZcbLqh22iWe52Oy9ivM7Lk6keffU7xIucJm1m2JUUYz930Njm2ijm1L5rwlkm13zYuYQS13; P00003=1408465522; P00010=1408465522; P01010=1501776000; P00007=08ZcbLqh22iWe52Oy9ivM7Lk6keffU7xIucJm1m2JUUYz930Njm2ijm1L5rwlkm13zYuYQS13; P00PRU=1408465522; P00002=%7B%22uid%22%3A%221408465522%22%2C%22user_name%22%3A%2218510725391%22%2C%22email%22%3A%22xiaoyan_jia1%40163.com%22%2C%22nickname%22%3A%22%5Cu7231%5Cu559d%5Cu996e%5Cu6599s%5Cu516c%5Cu4ef2%5Cu6668%22%2C%22pru%22%3A1408465522%2C%22type%22%3A11%2C%22pnickname%22%3A%22%5Cu7231%5Cu559d%5Cu996e%5Cu6599s%5Cu516c%5Cu4ef2%5Cu6668%22%7D; P000email=xiaoyan_jia1%40163.com; QC160=%7B%22u%22%3A%2218510725391%22%2C%22lang%22%3Afalse%2C%22local%22%3A%7B%22name%22%3A%22%E4%B8%AD%E5%9B%BD%E5%A4%A7%E9%99%86%22%2C%22init%22%3A%22Z%22%2C%22rcode%22%3A48%2C%22acode%22%3A%2286%22%7D%2C%22type%22%3A%22p%22%7D; QC911=%2Ca%2C; QC006=dvp8siolnl5z9noyqsawy4ke; Hm_lvt_53b7374a63c37483e5dd97d78d9bb36e=1501744707; _ga=GA1.2.2099195777.1501754894; __dfp=a03f42a0ff28c54146a475515ac6107716ac525722f5524a60655b7c247897c14e@1504346712080@1501754712080; T00404=bcd404d21b7724fa0b932f06b949a6b4; pps_client_ver2=6.0.46.4598", "Proxy-Connection": "keep-alive"},
        "request_content" : ''
    }
    :rtype: a tuple, if exists, return (True, message), else return (False, {})

    """
    message = {
        "method": "",
        "url" : "",
        "param" : "",
        "type" : "ssti",
        "info" : "[server side template injection]",
    }

    # the payload and anchor, for now only got one
    anchor = "57183746103"
    url = task['url']
    method = task['method']
    headers = task['request_header']
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
            if is_json_data(data):
                isjson = True
                query_string = urllib.urlencode(json.loads(data))
            else:
                query_string = data

        query_dict_list = Pollution(query_string, ssti_payload, isjson=isjson).payload_generate()
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

    # generate payloads
    # urlQueue = Queue.Queue()

    # url = task["url"]
    # u = urlparse.urlparse(url)
    # # if query, split it to dict, and directly replace orignal value
    # # maybe only use replace?????
    # if task["method"] == "GET":
    #     if u.query:
    #         try:
    #             query_dict = dict(urlparse.parse_qsl(u.query))
    #             for keys in query_dict:
    #                 tmp_query = ""
    #                 for payload in ssti_payload:
    #                     for in_keys in query_dict:
    #                         if in_keys == keys:
    #                             tmp_query += in_keys + "=" +  query_dict[in_keys] + payload
    #                         else:
    #                             tmp_query += in_keys + "=" + query_dict[in_keys]
    #                         tmp_query += "&"
    #                     tmp_query = tmp_query[:-1] # remove last &
    #                     tmp_url = u.scheme + "://" + u.netloc + u.path + "?" + tmp_query
    #                     _ = copy.deepcopy(task)
    #                     _["url"] = tmp_url
    #                     urlQueue.put(_)
    #                     del _
    #         except Exception as e:
    #             logger.info("[-] [Error] [SSTI] [splitUrl] " + repr(e))
    #     # path = /aa/bb/cc.html -> [/{{}}/bb/cc.html, /aa/{{}}/cc.html, ], ignore /aa-bb/cc-dd for now
    #     if u.path:
    #         path_list = u.path.split("/")
    #         for path in path_list:
    #             if path and "." not in path: # ignore usless path and last type path, i.e.  ignore "", "xxx.html"
    #                 for payload in ssti_payload:
    #                     tmp_path = u.path.replace(path, payload)

    #                     tmp_url = u.scheme + "://" + u.netloc + tmp_path + "?" + u.query
    #                     _ = copy.deepcopy(task)
    #                     _["url"] = tmp_url
    #                     urlQueue.put(_)
    #                     del _

    # elif task["method"] == "POST":
    #     # ingore json format
    #     post_content = task["request_content"]
    #     if "{" in post_content and ":" in post_content and "=" not in post_content:
    #         pass
    #     elif "multipart/form-data" in task["request_header"]["Content-Type"]:
    #         pass
    #     else:
    #         try:
    #             post_dict = dict(urlparse.parse_qsl(post_content))
    #             # direct replace is not correct,  if a=1%b=12 ,the result maybe a={}&b={}2
    #             for keys in post_dict:
    #                 tmp_post = ""
    #                 for payload in ssti_payload:
    #                     for in_keys in post_dict:
    #                         if in_keys == keys:
    #                             tmp_post += in_keys + "=" + post_dict[in_keys] + payload
    #                         else:
    #                             tmp_post += in_keys + "=" + post_dict[in_keys]
    #                         tmp_post += "&"
    #                     tmp_post = tmp_post[:-1]
    #                     _ = copy.deepcopy(task)
    #                     _["request_content"] = tmp_post
    #                     urlQueue.put(_)
    #                     del _
    #         except Exception as e:
    #             logger.error("[-] [ERROR] [SSTI] [splitUrl] " + repr(e))


    # #verify
    # found = False
    # while not urlQueue.empty():
    #     item = urlQueue.get()
    #     print item["url"]
    #     try:
    #         logger.info("[+] [Info] [SSTI] [verify] Parseing:\t" + item["url"] + "###" + item["request_content"] )
    #         if item["method"] == "POST":
    #             ret = requests.post(item["url"], item["request_content"], headers=item["request_header"], timeout=10, verify=False, allow_redirects=False)
    #             if anchor in ret.content:
    #                 message["url"] = item["url"]
    #                 message["method"] = "POST"
    #                 message["param"] = item["request_content"]
    #                 found = True
    #                 break

    #         elif item["method"] == "GET":
    #             ret = requests.get(item["url"], headers=item["request_header"], timeout=10, verify=False, allow_redirects=False)
    #             if anchor in ret.content:
    #                 message["url"] = item["url"]
    #                 message["method"] = "GET"
    #                 found = True
    #                 break
    #     except Exception as e:
    #         logger.error("[-] [Error] [SSTI] [verify] " + repr(e))
    # while not urlQueue.empty():
    #     urlQueue.get()

    # if found:
    #     return (True, message)
    # else:
    #     return (False, {})




if __name__ == '__main__':
    item1={
        "url": "http://passport.iqiyi.com/apis/reglogin/generate_tauthcookie.action?agenttype=30&authcookie=90TWerf7fSFlzc2dPRTcPtBia9MfuLzpSgQLRfm3E1LflenPtzym25hm3v2WEDrJjrMwC99&cb_url=http%3A%2F%2Fwww.iqiyi.com%2Fu%2Faccountset%2F%3Fqyid%3Dmqaguvg2qatzipbhxzd2sbcxadxumaaz&dfp=c018a02bd5351647c5b0793474e48f6ad9a19f47fce0bdda3352149fc8be046a62&ptid=01012001020000000000",
        "request_header": {"Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.6", "Proxy-Connection": "keep-alive", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8", "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36", "DNT": "1", "Host": "passport.iqiyi.com", "Cookie": "P00004=611242028.1502177691.ba8b02e645; QC005=2346048e8e118e0662a994cb3bf7c4f5; P00001=968HSCuKkhqcbTOKpCnSFjrkm2kwJ3I5H6eIVz9FvDryK4VFQWWIsW3yI9y3Mzm1g3gedb; P00003=1409979958; P00010=1409979958; P01010=1502208000; P00007=968HSCuKkhqcbTOKpCnSFjrkm2kwJ3I5H6eIVz9FvDryK4VFQWWIsW3yI9y3Mzm1g3gedb; P00PRU=1409979958; P00002=%7B%22uid%22%3A%221409979958%22%2C%22user_name%22%3A%2218892088148%22%2C%22email%22%3A%22%22%2C%22nickname%22%3A%22%5Cu7231%5Cu6dae%5Cu706b%5Cu9505%5Cu7684%5Cu516c%5Cu826f%5Cu60dc%5Cu96ea%22%2C%22pru%22%3A1409979958%2C%22type%22%3A11%2C%22pnickname%22%3A%22%5Cu7231%5Cu6dae%5Cu706b%5Cu9505%5Cu7684%5Cu516c%5Cu826f%5Cu60dc%5Cu96ea%22%7D; P000email=18892088148; QC001=1; QC007=DIRECT; QC006=d5reawy4z0pja0fwp8qn6cml; QC008=1502177879.1502177879.1502178457.2; QC009=95f5a5e8437676dc", "Upgrade-Insecure-Requests": "1", "Accept-Encoding": "identity"},
        "request_content": "",
        "method": "GET"
    }

    item2 = {
        "url" : "http://passport.iqiyi.com/apis/user/info.action",
        "method" : "POST",
        "request_content" : "fields=userinfo&authcookie=08ZcbLqh22iWe52Oy9ivM7Lk6keffU7xIucJm1m2JUUYz930Njm2ijm1L5rwlkm13zYuYQS13&antiCsrf=f27a106511483ca372f0bac8d1f5c635&__POST=1&cb=1&agenttype=1&dfp=a09e5773e86a1e4537af92edfd6aed6e5bc19d797ac009e2a869115dca31a5993e&callback=window.parent.__CALLBACK__pbwehf",
        "request_header" : {"Origin": "http://vip.iqiyi.com", "Content-Length": "281", "Accept-Language": "en-US,en;q=0.8", "Proxy-Connection": "keep-alive", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Upgrade-Insecure-Requests": "1", "Host": "passport.iqiyi.com", "Referer": "http://vip.iqiyi.com/club/?src=604011_1", "Cache-Control": "max-age=0", "Cookie": "P00004=-898887952.1501743222.891ba158bb; QC005=437b5f59bacf7103319dfd55207aba05; P00001=08ZcbLqh22iWe52Oy9ivM7Lk6keffU7xIucJm1m2JUUYz930Njm2ijm1L5rwlkm13zYuYQS13; P00003=1408465522; P00010=1408465522; P01010=1501776000; P00007=08ZcbLqh22iWe52Oy9ivM7Lk6keffU7xIucJm1m2JUUYz930Njm2ijm1L5rwlkm13zYuYQS13; P00PRU=1408465522; P00002=%7B%22uid%22%3A%221408465522%22%2C%22user_name%22%3A%2218510725391%22%2C%22email%22%3A%22xiaoyan_jia1%40163.com%22%2C%22nickname%22%3A%22%5Cu7231%5Cu559d%5Cu996e%5Cu6599s%5Cu516c%5Cu4ef2%5Cu6668%22%2C%22pru%22%3A1408465522%2C%22type%22%3A11%2C%22pnickname%22%3A%22%5Cu7231%5Cu559d%5Cu996e%5Cu6599s%5Cu516c%5Cu4ef2%5Cu6668%22%7D; P000email=xiaoyan_jia1%40163.com; QC160=%7B%22u%22%3A%2218510725391%22%2C%22lang%22%3Afalse%2C%22local%22%3A%7B%22name%22%3A%22%E4%B8%AD%E5%9B%BD%E5%A4%A7%E9%99%86%22%2C%22init%22%3A%22Z%22%2C%22rcode%22%3A48%2C%22acode%22%3A%2286%22%7D%2C%22type%22%3A%22p%22%7D; QC911=%2Ca%2C; Hm_lvt_53b7374a63c37483e5dd97d78d9bb36e=1501744707; _ga=GA1.2.2099195777.1501754894; T00404=bcd404d21b7724fa0b932f06b949a6b4; pps_client_ver2=6.0.46.4598; QC001=1; QC007=DIRECT; QC008=1498535221.1502182004.1502182004.5; QC006=dvp8siolnl5z9noyqsawy4ke; QC010=170508320; __dfp=a09e5773e86a1e4537af92edfd6aed6e5bc19d797ac009e2a869115dca31a5993e@1504336348706@1501744348706", "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36 Falcon/5.0.7.1", "Content-Type": "application/x-www-form-urlencoded", "Accept-Encoding": "identity"},
    }


    verify(item1)
