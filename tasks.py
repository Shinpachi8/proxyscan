#!/usr/bin/env python
# coding=utf-8

from celery import Celery
import os
import glob
import importlib

from plugins.config import *


app = Celery("tasks", broker="redis://localhost/1")


@app.task
def scan(task):
    plugins = importpoc()
    for plugin in plugins:
        (found, message) = plugin(task)
        if found:
            logger.info("[VULN FOUND] {}".format(message))




def importpoc():
    plugins = glob.glob("plugins/poc*.py")
    plugins = [plugin[:-3] for plugin in plugins]
    pluginsfiles = [plugin.replace("/", ".") for plugin in plugins]

    plugins = []
    for plugin in pluginsfiles:
        module = importlib.import_module(plugin)
        if hasattr(module, "verify"):
            plugins.append(getattr(module, "verify"))
    print plugins
    # print dir(plugins[0])
    return plugins
#         module = importlib.import_module('plugin.' + str(f)[:-3])
#         #plugins.append(module)
#         if hasattr(module, "test"):
#             plugin = getattr(module, "test")
#             plugins.append(plugin)

if __name__ == '__main__':
    importpoc()
