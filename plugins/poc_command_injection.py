#!/usr/bin/env python
# -*- coding:utf-8 -*-

import requests
import time
import copy
import urlparse
import copy
import base64
from config import *
from lib.common import *




def verify(task):
    print "===============\n now in ci\n=================="
    """
    this function aim to detect command injection. for now, only detect the output and the dnslog,
    here we sleep(4) to wait the dnslog ,
    :param: task, the proxy request item
    :rtype: a tuple, if exists, return(True, message), else return(False, {})
    """
    # if task["method"] != "GET":
    #     return (False, {})
    message = {
        "method": "",
        "url" : "",
        "param" : "",
        "type" : "ci",
        "info" : "[command injection]",
    }

    # dns loc
    url = task['url']
    method =  task['method']
    headers = task['request_header']
    target  = base64.b64encode(url).replace('=', '')
    data = task['request_content'] if method == 'POST' else None
    hj = THTTPJOB(url, method=method, headers=headers, data=data)
    # item_list = []
    # base_url = task['url']

    url_parse = urlparse.urlparse(url)
    if url_parse.query == "" and method=='GET':
        return (False, {})

    payload_list = copy.copy(command_injection_payloads)
    payload_list = [p.replace('{domain}', target) for p in payload_list]

    # get query:
    isjson = False
    found = False
    if method == 'GET':
        query = hj.url.get_query
    else:
        if is_json(hj.data):
            query = urllib.urlencode(json.loads(hj.data))
            isjson = True
        else:
            query = hj.data

    # generate pollution
    payload_dict = Pollution(query, payload_list).payload_generate()
    for payload in payload_dict:
        '''
        if method == 'GET':
            hj.url.get_dict_query = payload
        else:
            if isjson:
                hj.data = json.dumps(payload)
            else:
                hj.data = urllib.urlencode(payload)
        '''
        hj.request_param_dict = payload
        # print payload

        hj.request()

    return (False, {})





    # get target pre


    # query = dict(urlparse.parse_qsl(url_parse.query))
    # # first makeup payload, and this is add,
    # for keys in query.keys():
    #     try:
    #         for payload_item in fuzz_payload:
    #             #toreplace_payload = payload_item.encode("utf-8")

    #             payload_item = query[keys] + payload_item
    #             # makeup the all paramters
    #             params = ""
    #             for in_key in query.keys():
    #                 if in_key == keys:
    #                     params += in_key + "=" + payload_item
    #                 else:
    #                     params += in_key + "=" + query[in_key]
    #                 params += "&"
    #             params = params[:-1]

    #             attack_url = url_parse.scheme + "://" + url_parse.netloc + url_parse.path + "?" + params
    #             _ = copy.deepcopy(task)
    #             _["url"] = attack_url

    #             item_list.append(_)
    #     except Exception as e:
    #         logger.error(repr(e))

    # for item in item_list:
    #     try:
    #         requests.get(item["url"], headers=item["request_header"], verify=False, allow_redirects=True, timeout=10)
    #     except Exception as e:
    #         logger.error(repr(e))

    # # replace the headers
    # for payload in fuzz_payload:
    #     task["request_header"]["User-Agent"] = payload
    #     try:
    #         requests.get(task["url"], headers=task["request_header"], timeout=10)
    #     except Exception as e:
    #         logger.error(repr(e))

    # # verify the log
    # time.sleep(5)
    # dnsApi = "http://dnslog.niufuren.cc/api/dns/devil/{}/"
    # rep = requests.get(dnsApi.format(tag))
    # if "True" in rep.text:
    #     message["url"] = task["url"]
    #     message["param"] = tag
    #     message["method"] = task["method"]
    #     save_to_databases(message)
    #     return (True, message)
    # else:
    #     return (False, {})



if __name__ == '__main__':
    """
    with open("payload.json", "r") as f:
        lines = json.load(f)
    print len(lines)
    for i in lines:
        print i

    """
    item = {
        "method" : "POST",
        "url" : "http://127.0.0.1/dvwa/vulnerabilities/exec/#",
        "request_header" : {"Accept-Language": "en-US,en;q=0.8", "Accept-Encoding": "identity", "Accept": "*/*", "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36 Falcon/5.0.7.1", "Referer": "http://paopaoquan.iqiyi.com/feed", "Cookie": "P00004=-898887952.1501743222.891ba158bb; QC008=1498535221.1501744345.1501744345.3; QC005=437b5f59bacf7103319dfd55207aba05; P00001=08ZcbLqh22iWe52Oy9ivM7Lk6keffU7xIucJm1m2JUUYz930Njm2ijm1L5rwlkm13zYuYQS13; P00003=1408465522; P00010=1408465522; P01010=1501776000; P00007=08ZcbLqh22iWe52Oy9ivM7Lk6keffU7xIucJm1m2JUUYz930Njm2ijm1L5rwlkm13zYuYQS13; P00PRU=1408465522; P00002=%7B%22uid%22%3A%221408465522%22%2C%22user_name%22%3A%2218510725391%22%2C%22email%22%3A%22xiaoyan_jia1%40163.com%22%2C%22nickname%22%3A%22%5Cu7231%5Cu559d%5Cu996e%5Cu6599s%5Cu516c%5Cu4ef2%5Cu6668%22%2C%22pru%22%3A1408465522%2C%22type%22%3A11%2C%22pnickname%22%3A%22%5Cu7231%5Cu559d%5Cu996e%5Cu6599s%5Cu516c%5Cu4ef2%5Cu6668%22%7D; P000email=xiaoyan_jia1%40163.com; QC160=%7B%22u%22%3A%2218510725391%22%2C%22lang%22%3Afalse%2C%22local%22%3A%7B%22name%22%3A%22%E4%B8%AD%E5%9B%BD%E5%A4%A7%E9%99%86%22%2C%22init%22%3A%22Z%22%2C%22rcode%22%3A48%2C%22acode%22%3A%2286%22%7D%2C%22type%22%3A%22p%22%7D; QC911=%2Ca%2C; QC006=dvp8siolnl5z9noyqsawy4ke; Hm_lvt_53b7374a63c37483e5dd97d78d9bb36e=1501744707; _ga=GA1.2.2099195777.1501754894; __dfp=a03f42a0ff28c54146a475515ac6107716ac525722f5524a60655b7c247897c14e@1504346712080@1501754712080; T00404=bcd404d21b7724fa0b932f06b949a6b4; pps_client_ver2=6.0.46.4598", "Proxy-Connection": "keep-alive"},
        "request_content" : 'ip=127.0.0.1&Submit=Submit'
    }
    item['request_header']['Cookie'] = 'security=low; csrftoken=L03N8fzw2keuw4mpwKn0TIoBJXTBxFDHkpQepzsiYXFtu3PjJ39n2jupRXgXk8IH; sessions=%7B%7D; sessionid=uqh3pox9yzynu02eg5wy004ktm18z6lm; PHPSESSID=5rfvtl8n5nr68prqfs4rfakre7'

    verify(item)







