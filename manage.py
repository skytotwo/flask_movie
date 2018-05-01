# -*- coding:utf-8 -*-
__author__ = 'jolly'
__date__ = '2018/4/17 下午10:10'
from app import app
from flask_script import Manager

#线上使用命令行启动
# manage = Manager(app)

if __name__ == "__main__":
    #本机启动
    app.run(debug=True, port=8000)
    #服务器启动
    # manage.run()