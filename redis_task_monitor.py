#!/usr/bin/env python
# coding=utf-8



import threading
import glob
import importlib
from plugins.lib.common import *

def importpoc():
    plugins = glob.glob("plugins/poc*.py")
    plugins = [plugin[:-3] for plugin in plugins]
    pluginsfiles = [plugin.replace("/", ".") for plugin in plugins]

    plugins = []
    for plugin in pluginsfiles:
        module = importlib.import_module(plugin)
        if hasattr(module, "verify"):
            plugins.append(getattr(module, "verify"))
    # print plugins
    # print dir(plugins[0])
    return plugins

def plugin_num():
    plugins = glob.glob("plugins/poc*.py")
    return len(plugins)

lock = threading.Lock()

class Monitor(threading.Thread):
    plugins = []
    STOP_ME = False
    def __init__(self):
        threading.Thread.__init__(self)
        self.conn = RedisUtil(RedisConf.db, RedisConf.host, RedisConf.password)

    def run(self):
        while True:
            if Monitor.STOP_ME:
                break

            with lock:
                if plugin_num != len(Monitor.plugins):
                    Monitor.plugins = importpoc()

            task = None
            with lock:
                task = self.conn.task_fetch(RedisConf.taskqueue)
            
            if task:
                task = json.loads(task)
                for p in Monitor.plugins:
                    (result, message) = p(task)
                    if result:
                        # save to mysql
                        logger.info("[found] Message={}".format(message))
            else:
                logger.info("now, we have no task and sleep..")
                time.sleep(600)

                


def start_point():
    threads = []
    for i in xrange(30):
        t = Monitor()
        t.setDaemon = True
        threads.append(t)
    
    for t in threads:
        t.start()
    
    while True:
        try:
            if threading.active_count <= 1:
                Monitor.STOP_ME = True
                break
            else:
                time.sleep(1)
        except KeyboardInterrupt as e:
            Monitor.STOP_ME = True
            logger.info("User Killed to Break")
            break
        except Exception as e:
            logger.info(repr(e))





def main():
    print RedisConf.db

if __name__ == '__main__':
    main()

