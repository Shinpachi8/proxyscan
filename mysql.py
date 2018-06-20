# encoding: utf-8

from __future__ import absolute_import

from config import mysqldb_conn

import pymysql
import pymysql.cursors
import json
import time

def timestamp_datetime(value):
    format = '%Y-%m-%d %H:%M:%S'
    value = time.localtime(value)
    dt = time.strftime(format, value)
    return dt

class MysqlInterface(object):
    """docstring for MysqlInterface"""

    def __init__(self):
        self.connection = self.init()

    @staticmethod
    def init():
        # Connect to the database
        connection = pymysql.connect(
                host = mysqldb_conn.get('host'),
                user = mysqldb_conn.get('user'),
                password = mysqldb_conn.get('password'),
                db = mysqldb_conn.get('db'),
                charset = mysqldb_conn.get('charset'),
                cursorclass=pymysql.cursors.DictCursor)
        return connection

    def insert_result(self, result):
        with self.connection.cursor() as cursor:
            # Create a new record
            sql = """INSERT INTO `capture` (
                `extension`,
                `url`,
                `status_code`,
                `date_time`,
                `host`,
                `path`,
                `method`,
                `request_content`,
                `request_header`
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"""

            extension = result.get('extension'),
            url = result.get('url'),
            status_code = result.get('status_code'),
            date_time = result.get('date_time'),
            # 突然发现content也是有点用的，现在先不改了，如果真的需要再改一下吧
            # content = result.get('content')

            host = result.get('host'),

            path = result.get('path'),
            method = result.get('method'),

            request_content = result.get('request_content'),
            request_header = json.dumps(result.get('request_header'))

            cursor.execute(sql, (
                extension,
                url,
                status_code,
                date_time,
                host,
                path,
                method,
                request_content,
                request_header)
            )

            # connection is not autocommit by default. So you must commit to save
            # your changes.
            self.connection.commit()

    def close(self):
        if self.connection:
            return self.connection.close()

    def __del__(self):
        """close mysql database connection"""
        self.close()



