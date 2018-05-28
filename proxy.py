#!/usr/bin/env python
# encoding: utf-8

import sys
import argparse
import Queue
import threading
import time
import re
import urllib
import copy
import urlparse
import requests
import hashlib
import json
import logging
import redis
from mitmproxy import flow, proxy, controller, options
from mitmproxy.proxy.server import ProxyServer
from parser import ResponseParser
from termcolor import cprint
from mysql import MysqlInterface
# from tasks import scan
from plugins.lib.common import *


requests.packages.urllib3.disable_warnings()

class BlueProxy(flow.FlowMaster):

    def __init__(self, opts, server, state):
        super(BlueProxy, self).__init__(opts, server, state)
        #self.task_queue = Queue.Queue()
        #self.cif_task_queue = Queue.Queue()
        #self.cif_result_queue = Queue.Queue()
        self.url_queue = Queue.Queue()
        self.data_queue = Queue.Queue()
        #self.ssti_task_queue = Queue.Queue()
        self.STOP_ME = False
        self.start_time = time.time()
        self.url_count = 0
        self.redis_conn = RedisUtil(RedisConf.db, RedisConf.host)

        #GET 重复&&相似度
        self.get_dupl  = [[], []]
        #POST 重复&&相似度
        self.post_dupl = [[], []]
        #统计参数, 无参数动态文件
        self.count_dupl = {'query':{}, 'script':{}}

        self.check_group = Queue.Queue()

        # get command injection fuzzing class objection
        # self.cifuzz = FuzzCIF(self.cif_task_queue, self.cif_result_queue)
        # get server side template injection object
        # self.sstinjection = ssti(self.ssti_task_queue, self.cif_result_queue)

        # threading.lock
        self.lock = threading.Lock()

        threading.Thread(target=self.duplicate_thread).start()
        threading.Thread(target=self._print_msg).start()
        threading.Thread(target=self.send2redis).start()
        #threading.Thread(target=self.save_cif_result).start()

        #插入URL到本地或远程任务队列中
        # threading.Thread(target=self.put_thread).start()

    def print_data(self):
        while not self.STOP_ME:
            try:
                result = self.task_queue.get(timeout=0.1)
                #print result
                time.sleep(0.1)
            except Exception as e:
                continue


    def _print_msg(self):
        cprint('-'*35, 'cyan')
        while not self.STOP_ME:
            try:
                msg = '%s TOTAL|  %.1f Sec Running' % (
                    self.url_count, time.time() - self.start_time)
                sys.stdout.write('\r{}'.format(msg))
                sys.stdout.flush()
                time.sleep(1)
            except Exception, e:
                print 'error_in_print_msg={}'.format(repr(e))

    def duplicate_thread(self):
        while not self.STOP_ME:
            try:
                result = self.url_queue.get(timeout=0.1)
                if result['method'] == 'GET':
                    data = result['url']
                    ret = self.duplicate('GET', [data])
                else:
                    data = {'postData':result['request_content'], 'url':result['url']}
                    ret = self.duplicate('POST', [data])
                if ret:
                    mysqldb_io = MysqlInterface()
                    mysqldb_io.insert_result(result)
                    #self.task_queue.put(result)
                    self.url_count += 1
            except Exception, e:
                time.sleep(1)
                #print str(e)
                continue

    # def put_thread(self):
    #     while not self.STOP_ME:
    #         try:
    #             task = self.task_queue.get()
    #             scan.delay(task)
    #         except Exception as e:
    #             print "[scan.delay] [error={}]".format(e)

    def md5(self, data):
        m = hashlib.md5()
        m.update(data)
        Hash = m.hexdigest()
        return Hash

    def rewrite(self, path):
        ascii = ' !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~'
        flags = ['/', '_', '-', ',', '&', '=', '!']
        ext = ''
        Hash = ''
        if re.match(r"(?i)/(.+)\.(html|htm|xhtml|xhtm|shtml|shtm)$",path):
            ext = path[path.rfind('.'):]
        path = path.replace(ext,'')
        r = '(\\' + '|\\'.join(flags) + ')'
        paths = re.split(r,path)
        for path in paths:
            if path:
                if path.replace('.','').isdigit():
                    #数字
                    Hash = Hash + '{{int}}'
                else:
                    if path not in flags:
                        for s in urllib.unquote(path):
                            if s not in ascii:
                                #中文
                                Hash = Hash + '{{^not_ascii^}}'
                                break
                        else:
                            #英文
                            Hash = Hash + '{{' + str(len(path)) + '}}'
                    else:
                        Hash = Hash + path
        Hash = Hash + ext
        return Hash

    def counts(self, hash, _type):
        if hash in self.count_dupl[_type]:
            self.count_dupl[_type][hash] += 1
        else:
            self.count_dupl[_type][hash]  = 1

    def duplicate(self, method, links):
        ret = []
        for link in links:
            if method == 'GET':
                Urlparse = urlparse.urlsplit(link)
                #完全重复计算值
                get_querys_1 = tuple(set(sorted([i for i in Urlparse.query.split('&')])))
                s = '{0}|{1}|{2}|{3}'.format(Urlparse.scheme, Urlparse.netloc, Urlparse.path, get_querys_1)
                hash_1 = self.md5(s)
                #完全重复判断
                if hash_1 in self.get_dupl[0]:
                    continue
                else:
                    self.get_dupl[0].append(hash_1)

                #无参数动态文件
                regex = re.match(r"(?i)(http|https)://[^\?]+\.(php|asp|aspx|jsp|jspx|do|action|xml|ashx|cgi|sh|pl)$",link.split('#')[0])

                #相似度计算值
                get_querys_2 = tuple(set(sorted([i.split('=')[0] for i in Urlparse.query.split('&')])))
                s = '{0}|{1}|{2}|{3}'.format(Urlparse.scheme, Urlparse.netloc, Urlparse.path, get_querys_2)
                hash_2 = self.md5(s)

                #伪静态
                if Urlparse.query == '' and not regex:
                    path = Urlparse.path
                    path = self.rewrite(path)
                    s = '{0}|{1}|{2}|{3}'.format(Urlparse.scheme, Urlparse.netloc, path, get_querys_2)
                    hash_2 = self.md5(s)
                    if self.get_dupl[1].count(hash_2) >= 5:
                        continue
                    else:
                        self.get_dupl[1].append(hash_2)
                #正常型URL
                #单参数&&无参数
                elif (Urlparse.query != '' and len(get_querys_2) == 1) or regex:
                    path = Urlparse.path
                    path = self.rewrite(path)
                    if hash_2 in self.get_dupl[1]:
                        continue
                    else:
                        if regex:
                            s = '{0}|{1}|{2}'.format(Urlparse.scheme, Urlparse.netloc, path)
                            script_hash = self.md5(s)
                            if self.count_dupl.get('script').get(script_hash) > 10:
                                continue
                            self.counts(script_hash, 'script')
                        else:
                            s = '{0}|{1}|{2}'.format(Urlparse.scheme, Urlparse.netloc, get_querys_2)
                            query_hash_1 = self.md5(s)
                            s = '{0}|{1}|{2}|{3}'.format(Urlparse.scheme, Urlparse.netloc, path, get_querys_2)
                            query_hash_2 = self.md5(s)
                            if self.count_dupl.get('query').get(query_hash_1) > 20:
                                continue
                            elif self.count_dupl.get('query').get(query_hash_2) > 5:
                                hash_2 = query_hash_2
                                if hash_2 in self.get_dupl[1]:
                                    continue
                            self.counts(query_hash_1, 'query')
                            self.counts(query_hash_2, 'query')
                        self.get_dupl[1].append(hash_2)
                #多参数
                else:
                    path = Urlparse.path
                    path = self.rewrite(path)
                    if self.get_dupl[1].count(hash_2) >= 5:
                        continue
                    else:
                        s = '{0}|{1}|{2}'.format(Urlparse.scheme, Urlparse.netloc, get_querys_2)
                        query_hash_1 = self.md5(s)
                        s = '{0}|{1}|{2}|{3}'.format(Urlparse.scheme, Urlparse.netloc, path, get_querys_2)
                        query_hash_2 = self.md5(s)
                        if self.count_dupl.get('query').get(query_hash_1) > 30:
                            continue
                        elif self.count_dupl.get('query').get(query_hash_2) > 10:
                            hash_2 = query_hash_2
                            if hash_2 in self.get_dupl[1]:
                                continue
                        self.counts(query_hash_1, 'query')
                        self.counts(query_hash_2, 'query')
                        self.get_dupl[1].append(hash_2)
                ret.append(link)
            elif method == 'POST':
                data = link['postData']
                link = link['url']
                Urlparse = urlparse.urlsplit(link)
                #完全重复计算值
                get_querys_1  = tuple(set(sorted([i for i in Urlparse.query.split('&')])))
                post_querys_1 = tuple(set(sorted([i for i in data.split('&')])))
                s = '{0}|{1}|{2}|{3}|{4}'.format(Urlparse.scheme, Urlparse.netloc, Urlparse.path, get_querys_1, post_querys_1)
                hash_1 = self.md5(s)
                #完全重复判断
                if hash_1 in self.post_dupl[0]:
                    continue
                else:
                    self.post_dupl[0].append(hash_1)

                #相似度计算值
                get_querys_2 = tuple(set(sorted([i.split('=')[0] for i in Urlparse.query.split('&')])))
                #POST XML 不常见 按GET参数去重
                if re.match(r"(?i)<\?xml",data):
                    post_querys_2 = ('',)
                #POST JSON
                elif re.match(r"{(.+):(.+)}$",data):
                    try:
                        data = json.loads(data).keys()
                        post_querys_2 = tuple(set(sorted([i for i in data])))
                    except:
                        post_querys_2 = ('',)
                #正常型URL
                else:
                    post_querys_2 = tuple(set(sorted([i.split('=')[0] for i in data.split('&')])))

                s = '{0}|{1}|{2}|{3}|{4}'.format(Urlparse.scheme, Urlparse.netloc, Urlparse.path, get_querys_2, post_querys_2)
                hash_2 = self.md5(s)

                #GET单参数&&无参数
                if (Urlparse.query != '' and len(get_querys_2) == 1) or Urlparse.query == '':
                    #POST单参数&&无参数
                    if (data != '' and len(post_querys_2) == 1) or data == '':
                        if hash_2 in self.post_dupl[1]:
                            continue
                        else:
                            self.post_dupl[1].append(hash_2)
                    #POST多参数
                    else:
                        if self.post_dupl[1].count(hash_2) >= 5:
                            continue
                        else:
                            self.post_dupl[1].append(hash_2)
                #GET多参数
                else:
                    if self.post_dupl[1].count(hash_2) >= 5:
                        continue
                    else:
                        self.post_dupl[1].append(hash_2)
                _ = {'url':link, 'postData':data}
                ret.append(_)
        return ret

    def run(self):
        try:
            flow.FlowMaster.run(self)
        except KeyboardInterrupt:
            self.shutdown()
            #self.cifuzz.terminate()
            self.STOP_ME = True
            print "Exit!"

    @controller.handler
    def request(self, msg):
        msg.request.anticache()
        msg.request.anticomp()

    @controller.handler
    def response(self, msg):
        try:
            parser = ResponseParser(msg).parser_data()
            if parser:
                self.url_queue.put(parser)
                self.data_queue.put(parser)
                #data = json.dumps(parser)
                #self.redis_conn.task_push(RedisConf.taskqueue, data)
        except Exception, e:
            print e

    def send2redis(self):
        while not self.STOP_ME:
            try:
                data = self.data_queue.get()
                data = json.dumps(data)
                self.redis_conn.task_push(RedisConf.taskqueue, data)
                print "RedisQueue Has {} items".format(self.redis_conn.task_count(RedisConf.taskqueue))
            except Exception as e:
                print repr(e)
                time.sleep(1)


        # memory overfull bug
        #print(len(self.state.flows))
        #print(self.state.flow_count())
        #self.state.clear()

def start_server(proxy_port, proxy_mode):
    LOGO = r'''
 ____  _               ____    ____     ___   __  __ __   __
| __ )| |_   _  ___   |  _ \  |  _ \   / _ \  \ \/ / \ \ / /
|  _ \| | | | |/ _ \  | |_) | | |_) | | | | |  \  /   \ V /
| |_) | | |_| |  __/  |  __/  |  _ <  | |_| |  /  \    | |
|____/|_|\__,_|\___|  |_|     |_| \_\  \___/  /_/\_\   |_|
           '''
    cprint(LOGO, 'cyan')
    cprint('[+] Starting Proxy On 0.0.0.0:{0}'.format(proxy_port), 'cyan')
    cprint('[+] Starting Proxy Mode: {0}'.format(proxy_mode), 'cyan')
    port = int(proxy_port)
    if proxy_mode == 'http':
        mode = 'regular'
    else:
        mode = proxy_mode

    opts = options.Options(
        listen_port=port,
        mode=mode,
        cadir="./ssl/",
        ssl_insecure=True,
        )

    config = proxy.ProxyConfig(opts)
    server = ProxyServer(config)
    state = flow.State()
    m = BlueProxy(opts, server, state)
    m.run()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("-p","--port",metavar="",default="8080",
        help="Bind Port Default 8080")
    parser.add_argument("-m","--mode",metavar="",choices=['http','socks5','transparent'],default="http",
        help="Proxy Mode (HTTP, Socks5, Transparent) Default http")
    args = parser.parse_args()
    try:
        port = args.port
        mode = args.mode
        start_server(port, mode)
    except KeyboardInterrupt:
        print "Exti!!!!!"
        sys.exit(1)
