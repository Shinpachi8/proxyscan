# 规定
1. 输入的值为dict类型, 从proxy中取出来的
    ```
    item = {
        "url" : "",
        "host" : "",
        "method" : "",
        "extension" : "",
        "date_time" : "",
        "path" : "",
        "status_code" :"",
        "reqeust_content" : "",
        "request_header" : {},

    }

    ```

2. backend的保存的消息格式如下:
    ```
    result = {
        "type" : "xss",
        "found" : False;
        "method" : "GET",
        "url" : "",
        "param" : "",
        "info" : "",
    }

    ```

3. TODO
    1. 将返回result中的found字段为True的结果保存到SQL数据库, 暂时未保存
    2. 一些配置如sqlmapapi的URL， redis的一些配置，包括payload的一些配置都放在配置文件而不是分别编码在其自己的py文件中
    3. 还有很多地方没有加try/catch， 完善的时候加一下


# 使用：
1. 安装celery[redis] `pip install 'celery[Redis]'`
2. 在proj/tasks.py中配置sqlmapapi的 url地址
3. 启动redis (如果工具类都写好了，可以将redis作为一个后台服务)
4. 启动 celery `celery -A worker proj -l info`
5. 启动redisMonitor  (同样可以作为一个后台进程运行)

6. 启动proxy进行拦包, 
