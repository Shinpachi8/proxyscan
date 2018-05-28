#!/usr/bin/env python
# coding=utf-8

import threading
import glob
import importlib
import sys
from plugins.lib.common import *


def importpoc():
    plugins = glob.glob("plugins/poc*.py")
    plugins = [plugin[:-3] for plugin in plugins]
    pluginsfiles = [plugin.replace("/", ".") for plugin in plugins]
    print pluginsfiles
    plugins = []
    for plugin in pluginsfiles:
        module = importlib.import_module(plugin)
        if hasattr(module, "verify"):
            plugins.append(getattr(module, "verify"))
        else:
            print 'Error'
    print plugins
    # print dir(plugins[0])
    return plugins


def plugin_num():
    plugins = glob.glob("plugins/poc*.py")
    return len(plugins)


lock = threading.Lock()


class Monitor(threading.Thread):
    plugins = []
    STOP_ME = False

    def __init__(self, lock):
        threading.Thread.__init__(self)
        self.conn = RedisUtil(RedisConf.db, RedisConf.host, RedisConf.password)
        self.lock = lock

    def run(self):
        while True:
            if Monitor.STOP_ME:
                break
            logger.info('[Monitor] [Info] Now We Has {} in Queue'.format(self.conn.task_count(RedisConf.taskqueue)))
            if plugin_num() != len(Monitor.plugins):
                Monitor.plugins = importpoc()
            self.lock.acquire()
            if plugin_num() != len(Monitor.plugins):
                Monitor.plugins = importpoc()
                print "Monitor.plugisn.len={}".format((Monitor.plugins))
            else:
                print "Monitor.plugins = {} and plulgin_num={}".format(len(Monitor.plugins), plugin_num())
            self.lock.release()
            print Monitor.plugins
            task = None
            self.lock.acquire()
            
            task = self.conn.task_fetch(RedisConf.taskqueue)
            logger.info('[xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx]\ntask={}\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n'.format(task))
            self.lock.release()

            # logger.info('[Monitor] [Task={}]'.format(task))
            if task:
                task = json.loads(task)
                logger.info('[Monitor] [Info] [URL={}]'.format(task['url']))
                for p in Monitor.plugins:
                    (result, message) = p(task)
                    if result:
                        # save to mysql
                        logger.info("[found] Message={}".format(message))
            else:
                sys.stdout.write('\r{}'.format("now, we have no task and sleep.."))
                time.sleep(1)




def start_point():
    threads = []
    for i in xrange(1):
        t = Monitor(lock)
        t.setDaemon(True)
        threads.append(t)

    for t in threads:
        t.start()

    while True:
        try:
            time.sleep(1)
        except KeyboardInterrupt as e:
            Monitor.STOP_ME = True
            logger.info("User Killed to Break")
            break
        except Exception as e:
            logger.info(repr(e))
    logger.info('User FUCK KILL, WHY NOT EXIT!')





def main():
    print RedisConf.db
    print plugin_num()
    start_point()
    # importpoc()

if __name__ == '__main__':
    main()

