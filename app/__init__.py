# -*- coding:utf-8 -*-
__author__ = 'jolly'
__date__ = '2018/4/17 下午10:08'

import os
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
import pymysql
from flask_redis import FlaskRedis

app = Flask(__name__)
#本机环境
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:123456@127.0.0.1:3306/flask_movie"
#服务器环境
# app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:123456@203.195.229.64:3306/flask_movie"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True
app.config["SECRET_KEY"] = "6df4d214a3114678aff357b2338d10d0"
#绑定redis地址，生成redis对象
app.config["REDIS_URL"] = "redis://127.0.0.1:6379/0"
app.config["UP_DIR"] = os.path.join(os.path.abspath(os.path.dirname(__file__)), "static/uploads/")
app.config["FC_DIR"] = os.path.join(os.path.abspath(os.path.dirname(__file__)), "static/uploads/users/")
app.config["UP_DIR_MV"] = os.path.join(os.path.abspath(os.path.dirname(__file__)), "static/uploads/movies/") #用于保存电影
app.config["UP_DIR_MVLOGO"] = os.path.join(os.path.abspath(os.path.dirname(__file__)), "static/uploads/mv_logo/") #用于保存电影封面
app.config["UP_DIR_PRLOGO"] = os.path.join(os.path.abspath(os.path.dirname(__file__)), "static/uploads/pr_logo/") #用于预告封面

app.debug = True  # (生产环境是False，开发环境是True)
db = SQLAlchemy(app)
rd = FlaskRedis(app)

from app.home import home as home_blueprint
from app.admin import admin as admin_blueprint

app.register_blueprint(home_blueprint)
app.register_blueprint(admin_blueprint, url_prefix="/admin")

# from flask.ext.moment import Moment
# moment = Moment(app)


@app.errorhandler(404)
def page_not_found(error):
    """
    404
    """
    return render_template("home/404.html"), 404