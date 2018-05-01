# -*- coding:utf-8 -*-
__author__ = 'jolly'
__date__ = '2018/4/17 下午10:09'


from flask import Blueprint

home = Blueprint("home", __name__)

import app.home.views