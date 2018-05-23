#!/usr/bin/env python
# coding=utf-8

from sqli_time.sqli_time_injection import run
from config import save_to_databases


def verify(task):
    message = {
        "method": "",
        "url" : "",
        "param" : "",
        "type" : "sqli-times",
        "info" : "[sqli times]",
    }
    url = task['url']
    method =  task['method']
    headers = task['request_header']
    data = task['request_content'] if method == 'POST' else None
    result = run(url, method, data, headers)
    if result:
        message['method'] = method
        message['url'] = result['target']
        save_to_databases(message)
        return True, message

    return (False,{})   
        # return message
    
