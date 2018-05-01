# -*- coding:utf-8 -*-
__author__ = 'jolly'
__date__ = '2018/4/17 下午10:08'


from flask import Blueprint

admin = Blueprint("admin", __name__)

import app.admin.views