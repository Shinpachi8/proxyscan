# encoding: utf-8

import urlparse
import re
import time
import os

class ResponseParser(object):
    def __init__(self, f):
        super(ResponseParser, self).__init__()
        self.flow = f
        self.content_type = self.get_content_type()
        self.extension = self.get_extension()
        self.ispass = self.capture_pass()

    def static_exts(self):
        STATIC_EXT =  ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg']
        STATIC_EXT += ['.js', '.css', '.exe', '.deb', '.cer']
        STATIC_EXT += ['.mp3', '.mp4', '.wma', '.wmv', '.avi', '.swf', '.flv']
        STATIC_EXT += ['.ppt', '.ttf', '.woff', '.woff2', '.doc', '.docx', '.xls', '.xlsx', '.xml', '.pdf', '.txt']
        STATIC_EXT += ['.apk', '.ipa', '.zip', '.rar', '.7z', '.gz', '.bz2', '.tar', '.iso', '.db']
        return STATIC_EXT
    def status_type(self):
        STATIC_TYPE =  ['image', 'bmp', 'video', 'audio', 'text/css']
        STATIC_TYPE += ['application/msword', 'application/vnd.ms-excel', 'application/vnd.ms-powerpoint', 'application/x-ms-wmd', 'application/x-shockwave-flash']
        return STATIC_TYPE


    def parse_url(self, url):
        _ = urlparse.urlparse(url, 'http')
        if not _.netloc:
            _ = urlparse.urlparse('http://' + url, 'http')
        return _.scheme, _.netloc, _.path if _.path else '/'

    def normurl(self, url):
        #协议://用户名:密码@子域名.域名.顶级域名:端口号/目录/文件名.文件后缀?参数=值#标志   
        url = urlparse.urlsplit(url)
        path = url.path if url.path else '/'
        path = re.compile(r'\\+').sub('/', path)
        end = '/' if path.endswith('/') else ''
        path = os.path.normpath(path)
        while path.find('//') >= 0:
            path = path.replace('//', '/')
        path = path.rstrip('/') + end
        url = urlparse.urlunsplit((url.scheme,url.netloc,path,url.query,url.fragment))
        return url

    def parser_data(self):
        if self.ispass:
            return
        result = {}
        result['url'] = self.normurl(self.flow.request.url)
        result['host'] = self.flow.request.host
        result['method'] = self.flow.request.method
        result['extension'] = self.extension
        result['date_time'] = self.getTime()
        result['path'] = self.get_path()
        result['status_code'] = self.flow.response.status_code
        result['request_content'] = self.flow.request.content
        result['request_header'] = self.parser_header(self.flow.request.headers)
        return result

    def get_content_type(self):

        if not self.flow.response.headers.get('Content-Type'):
            return ''
        return self.flow.response.headers.get('Content-Type').split(';')[:1][0]

    def capture_pass(self):
        scheme, netloc, path = self.parse_url(self.flow.request.url)
        if not netloc:
            return True
        if self.extension in self.static_exts():
            return True
        if not self.content_type:
            return False
        for t in self.status_type():
            if t in self.content_type:
                return True
        return False

    def get_extension(self):
        if not self.flow.request.path_components:
            return ''
        else:
            end_path = self.flow.request.path_components[-1:][0]
            split_ext = end_path.split('.')
            if not split_ext or len(split_ext) == 1:
                return ''
            else:
                return '.' + split_ext[-1:][0][:32].lower()
    
    def getTime(self):
        return time.strftime('%Y-%m-%d', time.localtime())

    def get_path(self):
        return '/{0}'.format("/".join(self.flow.request.path_components))
    @staticmethod
    def parser_header(header):
        headers = {}
        for key, value in header.iteritems():
            headers[key] = value
        return headers
