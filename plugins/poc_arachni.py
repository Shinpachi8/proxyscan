#!/usr/bin/env python
# coding=utf-8

from config import *
import requests
import time
import json
import yaml
from urlparse import parse_qs
from arachni.arachni_console import Arachni_Console

'''
class ArachniScan(object):

    """
    class for arachni scan by it's restful api
    """
    def __init__(self, arachni_domain, headers):
        self.arachni_domain = arachni_domain
        self.headers = headers
        self.arachni_headers = arachni_headers
        self.options = ARACHNI_OPTIONS.copy()

    def do_scan(self, url, cookie=None, post_data=None):
        """
        do scan for the url,
        OPTIONS，the OPTIONS which contains params to arachni rest server,
        from config.py and like: https://github.com/Arachni/arachni/wiki/REST-API

        :param: url,  the url to scan
        :param: cookie, the cookie that may be used in scan
        :rtype: scan id
        """

        self.options["url"] = url
        self.options["http"]["user_agent"] = self.headers["User-Agent"]
        if cookie is not None:
            self.options["http"]["cookie_string"] = cookie
            print "[do_scan] options.http.cookie_string= {}".format(self.options["http"]["cookie_string"])

        if post_data:
            post_dict = {
                "type": "form",
                "method": "post",
                "action": url,
                "inputs": {},
            }
            try:
                # if the post_data is json format, this will raise a exception
                post_dict['inputs'].update(parse_qs(post_data))
                yaml_string = yaml.safe_dump(post_dict, default_flow_style=False)
                self.options.update({
                    "plugins": {
                        "vector_feed": {
                            "yaml_string": yaml_string
                        }
                    }
                })
            except Exception as e:
                self.options.update({
                    "scope": {
                        "page_limit": 3
                    }
                })
            # pprint.pprint(options)
        else:
            self.options.update({
                "scope": {
                    "page_limit": 3
                }
            })




        loc = self.arachni_domain + "/scans"
        #options = json.dumps(self.options)
        try:
            req = requests.post(loc, headers=self.headers, json=self.options)
            if req.status_code == 500:
                # deal the situation that error happends
                #raise Exception
                print req.content
                return
            scanid = req.json()["id"]
            return scanid
        except Exception as e:
            logger.error("[do_scan] reason={}".format(repr(e)))
            return None

    def task_status(self, scanid):
        """
        through scanid return it's status, too see if "scanning" or "done"
        and if busy
        :param: scanid, the id belongs a task
        :rtype: (status, busy),
        """
        loc = self.arachni_domain + "/scans/{}/summary".format(scanid)
        try:
            req = requests.get(loc, headers=self.headers)
            # print req.content

            status = req.json()["status"]
            busy = req.json()["busy"]
            return (status, busy)
        except Exception as e:
            logger.error("[id_status] reason={}".format(repr(e)))
            return ("", "")

    def delete_task(self, scanid):
        """
        once the task done, retrive it's json data and delete the task
        :param: scanid, the id belongs to a task
        :rtype: None
        """
        loc = self.arachni_domain + "/scans/{}".format(scanid)
        try:
            req = requests.delete(loc, headers=self.headers)
        except Exception as e:
            logger.error("[delete_task] reason={}".format(repr(e)))

    def get_task_result(self, scanid):
        """
        when task was done, retrive the json data and parse it
        return the sql format
        :param: scanid, the id belongs a task
        :rtype: a list contans params the sqlarchimy needed
        (url, method, delta_time, vuln_name, severity, checks, proof, seed)
        """
        loc = self.arachni_domain + "/scans/{}/report.json".format(scanid)
        json_result = None
        try:
            req = requests.get(loc, headers=self.headers)
            json_result = req.json()
        except Exception as e:
            logger.error("[get_task_result] reason={}".format(repr(e)))
            return None
        if json_result:
            result = parse_arachni_json(json_result)
            return result
        else:
            return None

    def scan(self, url, cookie=None, post_data=None):
        """
        the scan process
        1. scan
        2. check status
        3. parse result
        4. save it to database
        """
        # scan
        scanid = self.do_scan(url, cookie, post_data)
        start_time = time.time()
        while True:
            if time.time() - start_time > arachni_timeout:
                break
            (status, busy) = self.task_status(scanid)
            logger.info("[scan] status={}, busy={}".format(status, busy))
            if status == "scanning":
                print "task is scanning, waiting..."


            if status == "done" and busy is False:
                break

            if status == "":
                return

            time.sleep(30)

        # parse result
        try:
            result = self.get_task_result(scanid)
        except Exception as e:
            result = ()

        return result
'''




def parse_arachni_json(data):
    """
    parse the arachni json result and return
    ((url, method, parameters, headers_string, \
    delta_time, vuln_name, severity, checks, proof, seed))

    +----------------+--------------+------+-----+---------+----------------+
    | Field          | Type         | Null | Key | Default | Extra          |
    +----------------+--------------+------+-----+---------+----------------+
    | id             | int(11)      | NO   | PRI | NULL    | auto_increment |
    | url            | mediumtext   | YES  |     | NULL    |                |
    | parameters     | mediumtext   | YES  |     | NULL    |                |
    | headers_string | mediumtext   | YES  |     | NULL    |                |
    | method         | varchar(15)  | YES  |     | NULL    |                |
    | delta_time     | varchar(50)  | YES  |     | NULL    |                |
    | vuln_name      | varchar(150) | YES  |     | NULL    |                |
    | severity       | varchar(30)  | YES  |     | NULL    |                |
    | checks         | varchar(150) | YES  |     | NULL    |                |
    | proof          | mediumtext   | YES  |     | NULL    |                |
    | seed           | mediumtext   | YES  |     | NULL    |                |
    | id_domain      | int(11)      | YES  | MUL | NULL    |                |
    +----------------+--------------+------+-----+---------+----------------+
    """
    result = []
    try:
        # data = json.loads(data)
        # url = data["options"]["url"]
        delta_time = data["delta_time"]
        assert "issues" in data
        for issue in data["issues"]:
            vuln_name = issue["name"]
            severity = issue["severity"]
            proof = issue["proof"] if "proof" in issue else ""
            checks = issue["check"]["name"]
            # get url
            # if headers_string does not exist, kill null
            # else fill it

            url = issue["request"]["url"] if "url" in issue["request"] else issue["vector"]["url"]
            # get method
            method = issue["request"]["method"]

            # get paramter
            parameters = ""
            if "parameters" in issue["request"] and issue["request"]["parameters"]:

                _ = issue["request"]["parameters"]
                for key in _:
                    parameters += key + "=" + _[key] + "&"

                parameters = parameters[:-1]

            # get headers_string
            headers_string = ""
            if "headers_string" in issue["request"] and issue["request"]["headers_string"]:
                headers_string = issue["request"]["headers_string"]

            seed = issue["vector"]["seed"] if "seed" in issue["vector"] else ""

            result.append((url, method, parameters, headers_string, delta_time, vuln_name, severity, \
                checks, proof, seed))
    except Exception as e:
        logger.error("[parse_arachni_json] reason={}".format(repr(e)))
        result = []
    return result





def verify(task):
    print "===================\nNow in poc_arachni\n========================="
    # arachniscan = ArachniScan(arachni_domain, arachni_headers)
    # arachniscan = Arachni_Console(url)
    url = task["url"]
    try:
        cookie = task["request_header"]["Cookie"]
    except:
        cookie = ''

    method = task['method']

    if task["method"] == "POST" and \
        "Content-Type" in task["request_header"] and \
        "form-data" not in task["request_header"]["Content-Type"]:
        post_data = task["request_content"]
    else:
        post_data = None

    # result = arachniscan.scan(url, cookie=cookie, post_data=post_data)
    agent = task['request_header']['User-Agent']
    scan = Arachni_Console(url, method=method, http_agent=agent,cookies=cookie, request_data=post_data)
    result = parse_arachni_json(json.loads(scan.get_report()))
    save_to_databases(result, arachni=True)
    return (False, {})


if __name__ == '__main__':
    #result = requests.get("http://127.0.0.1:7331//scans/f2bcdb1b6dca01db3e5c884be20f4e88/report.json", headers = arachni_headers)

    #x = parse_arachni_json(result.json())
    #print "================="
    #print x
    #save_to_databases(x, arachni=True)
    task = {'method': 'GET',
            'url': 'http://apisgame.iqiyi.com/datacache/tempdata/startgame/save?QC005=da23d481dd4fc8a3562226e8567e7ff0&spmid=&server_id=3006540&ad_ver=&uid=2387754763&area=1&fields=booked_status%2Cis_tourist&qipu_id=212782420&game_type=1&cf=&terminal=4&callback=o0o0oo0o&game_name=%25E5%2588%25BA%25E7%25A7%25A6%25E7%25A7%2598%25E5%258F%25B2&user_agent=chrome&authcookie=12O1k0RKm1xkCFZBvEpm2ANG6Lk8Dy7PWtGenXYCnN9PBerNLcAm3hoxcwb4DVM8E1Rzg22&server_order=40&game_id=6114&op_way=1',
            'request_header': {'Cookie': 'anyway=anyway', 'User-Agent': 'xlab'}}
    verify(task)
