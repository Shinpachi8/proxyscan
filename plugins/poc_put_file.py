#!/usr/bin/env python
# coding=utf-8

import requests
import urlparse
from config import *

def verify(task):
    message = {
        "method": "",
        "url" : "",
        "param" : "",
        "type" : "put file",
        "info" : "[put file]",
    }

    url = task['url']
    headers = task['headers']
    parsed_url = urlparse.urlparse(url)
    target = parsed_url.scheme + "://" + parsed_url.netloc + "/bugscan.txt"
    try:
        req = requests.put(target, '202cb962ac59075b964b07152d234b70', headers=headers)
        req = requests.get(target, headers=headers)
        if req.status_code == 200 and '202cb962ac59075b964b07152d234b70' in req.content:
            message['url'] = target
            message['param'] = '202cb962ac59075b964b07152d234b70'
            message['method'] = 'PUT'
            save_to_database(message)
            return (True, message)
    except Exception as e:
        pass
    
    return (False, {})
    