# -*- coding:utf-8 -*-
__author__ = 'jolly'
__date__ = '2018/2/5 下午10:10'

import os
from . import home
from flask import Flask, render_template, redirect, flash, session, Response, url_for, request, abort
from datetime import datetime, date
from functools import wraps
import uuid
import datetime
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename

from .forms import RegistForm, LoginForm, UserdetailForm, PwdForm, CommentForm
from app.models import User, Userlog, Comment, Preview, Tag, Movie, Moviecol
from app import db, app, rd


# 已登录就可以访问，否则重定向至登录。next页面为当前请求的url
def user_login_req(f):
    """
    登录装饰器
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("home.login", next=request.url))
        return f(*args, **kwargs)
    return decorated_function


@home.route("/register/", methods=["GET", "POST"])
def register():
    """
    会员注册
    """
    form = RegistForm()
    if form.validate_on_submit():
        data = form.data
        user = User(
            name=data["name"],
            email=data["email"],
            phone=data["phone"],
            pwd=generate_password_hash(data["pwd"]),
            uuid=uuid.uuid4().hex
        )
        db.session.add(user)
        db.session.commit()
        flash("注册成功！", "ok")
        return redirect(url_for("home.login"))
    return render_template("home/register.html", form=form)


@home.route("/login/", methods=["GET", "POST"])
def login():
    """
    登录
    """
    form = LoginForm()
    if form.validate_on_submit():
        data = form.data
        user = User.query.filter_by(name=data["name"]).first()
        if user: #如果查到有这个用户，如果不加判断的话，查出空值执行到后面就会报错
            if not user.check_pwd(data["pwd"]):#check_pwd的self.pwd就是user的pwd
                # 验证填的密码是否是 经过generate_password_hash哈希的密码 。若密码匹配，则返回真，否则返回假。
                flash("密码错误！", "err")
                return redirect(url_for("home.login"))
            session["user"] = user.name
            session["user_id"] = user.id
            userlog = Userlog( #用户登录日志
                user_id=user.id,
                ip=request.remote_addr
            )
            db.session.add(userlog)
            db.session.commit()
            return redirect(url_for("home.user"))
        else:
            flash("无该用户！", "err")
            return redirect(url_for("home.login"))
    return render_template("home/login.html", form=form)


@home.route("/logout/")
def logout():
    """
    退出登录
    """
    # 重定向到home模块下的登录。
    session.pop("user", None)
    session.pop("user_id", None)
    return redirect(url_for('home.login'))


# 修改文件名称
def change_filename(filename):
    fileinfo = os.path.splitext(filename) #分离文件名和扩展名
    filename = datetime.datetime.now().strftime("%Y%m%d%H%M%S") + str(uuid.uuid4().hex) + fileinfo[-1]
    return filename


@home.route("/user/", methods=["GET", "POST"])
@user_login_req
def user():
    """
    用户中心
    :return:
    """
    form = UserdetailForm()
    user_id = session["user_id"]
    user = User.query.get_or_404(user_id)
    if request.method == "GET":
        form.name.data = user.name
        form.email.data = user.email
        form.info.data = user.info
        form.phone.data = user.phone
    if form.validate_on_submit():
        data = form.data

        if not os.path.exists(app.config["FC_DIR"]):
            os.makedirs(app.config["FC_DIR"])
            os.chmod(app.config["FC_DIR"], "rw")

        if form.face.data != "":
            face = secure_filename(form.face.data.filename)
            user.face = change_filename(face)
            form.face.data.save(app.config["FC_DIR"] + user.face)

        #1、先判断填的用户名在库中有没有这条相关数据
        #2、如果有的话，就查出该条数据
        #3、然后判断，该条数据的用户名是否等于当前登录人的用户名
        #4、如果不是的话，就说明别人已经用了这个用户名，是的话就是说还是本人在用这个，就是正常更新
        #关键在于，同条数据本人可以更新，但不能与别人同名
        name_count = User.query.filter_by(name=data["name"]).count()
        if name_count == 1:
            userdata = User.query.filter_by(name=data["name"]).first()
            if userdata.name != user.name:
                flash("昵称已经存在！", "err")
                return redirect(url_for("home.user"))

        #与上同理
        email_count = User.query.filter_by(email=data["email"]).count()
        if email_count == 1:
            userdata2 = User.query.filter_by(email=data["email"]).first()
            if userdata2.email != user.email:
                flash("邮箱已经存在！", "err")
                return redirect(url_for("home.user"))

        # 与上同理
        phone_count = User.query.filter_by(phone=data["phone"]).count()
        if phone_count == 1:
            userdata3 = User.query.filter_by(phone=data["phone"]).first()
            if userdata3.phone != user.phone:
                flash("手机号码已经存在！", "err")
                return redirect(url_for("home.user"))

        user.name = data['name']
        user.phone = data['phone']
        user.info = data['info']
        user.email = data['email']
        db.session.add(user)
        db.session.commit()
        flash("修改个人信息成功！", "ok")
        return redirect(url_for('home.user'))
    return render_template("home/user.html", form=form, user=user)


@home.route("/pwd/", methods=["GET", "POST"])
@user_login_req
def pwd():
    """
    修改密码
    """
    form = PwdForm()
    if form.validate_on_submit():
        data = form.data
        user = User.query.filter_by(name=session["user"]).first()
        if not user.check_pwd(data["old_pwd"]):#check_pwd的self.pwd就是user的pwd
            flash("旧密码错误！", "err")
            return redirect(url_for('home.pwd'))
        user.pwd = generate_password_hash(data["new_pwd"])
        db.session.add(user)
        db.session.commit()
        flash("修改密码成功，请重新登录！", "ok")
        return redirect(url_for('home.logout'))
    return render_template("home/pwd.html", form=form)


# 用户中心-评论
@home.route("/comments/<int:page>", methods=["GET"])
@user_login_req
def comments(page=None):
    if page is None:
        page = 1
    user = User.query.filter_by(name=session["user"]).first()
    page_data = Comment.query.filter(
        user.id == Comment.user_id
    ).order_by(
        Comment.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("home/comments.html", page_data=page_data)


# 用户中心-登录日志
@home.route("/loginlog/<int:page>", methods=["GET"])
@user_login_req
def loginlog(page=None):
    if page is None:
        page = 1
    user = User.query.filter_by(name=session["user"]).first()
    page_data = Userlog.query.filter(
        user.id == Userlog.user_id
    ).order_by(
        Userlog.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("home/loginlog.html", page_data=page_data)


@home.route("/animation/")
def animation():
    """
    首页轮播动画,预告
    """
    data = Preview.query.all()
    return render_template("home/animation.html", data=data)


@home.route("/<int:page>/", methods=["GET"])
@home.route("/", methods=["GET"])
def index(page=None):
    """
    首页电影列表
    """
    tags = Tag.query.all()
    page_data = Movie.query
    # 标签
    tid = request.args.get("tid", 0) #第一次返回为0，后面点击带过来新的值
    if int(tid) != 0:
        page_data = page_data.filter_by(tag_id=int(tid))
    # 星级
    star = request.args.get("star", 0)
    if int(star) != 0:
        page_data = page_data.filter_by(star=int(star))
    # 时间
    time = request.args.get("time", 0)
    if int(time) != 0:
        if int(time) == 1:
            page_data = page_data.order_by(
                Movie.addtime.desc()
            )
        else:
            page_data = page_data.order_by(
                Movie.addtime.asc()
            )
    # 播放量
    pm = request.args.get("pm", 0)
    if int(pm) != 0:
        if int(pm) == 1:
            page_data = page_data.order_by(
                Movie.playnum.desc()
            )
        else:
            page_data = page_data.order_by(
                Movie.playnum.asc()
            )
    # 评论量
    cm = request.args.get("cm", 0)
    if int(cm) != 0:
        if int(cm) == 1:
            page_data = page_data.order_by(
                Movie.commentnum.desc()
            )
        else:
            page_data = page_data.order_by(
                Movie.commentnum.asc()
            )

    if page is None:
        page = 1

    page_data = page_data.paginate(page=page, per_page=8)
    p = dict( #初始化返回第一次全部为0
        tid=tid,
        star=star,
        time=time,
        pm=pm,
        cm=cm,
    )
    return render_template(
        "home/index.html",
        tags=tags,
        p=p,
        page_data=page_data)


@home.route("/search/<int:page>/")
def search(page=None):
    """
    搜索
    """
    if page is None:
        page = 1
    key = request.args.get("key", "")
    movie_count = Movie.query.filter(
        Movie.title.ilike('%' + key + '%')
    ).count() #返回搜索数量
    page_data = Movie.query.filter(
        Movie.title.ilike('%' + key + '%') #ilike进行模糊匹配
    ).order_by(
        Movie.addtime.desc()
    ).paginate(page=page, per_page=10)
    page_data.key = key #返回关键词
    return render_template("home/search.html", movie_count=movie_count, key=key, page_data=page_data)


@home.route("/play/<int:id>/<int:page>", methods=["GET", "POST"])
def play(id=None, page=None):
    """
    播放
    """
    # 查询出相关联的标签
    movie = Movie.query.join(Tag).filter(
        Tag.id == Movie.tag_id,
        Movie.id == int(id)
    ).first_or_404()

    #返回该电影的所有评论
    if page is None:
        page = 1
    page_data = Comment.query.join(
        Movie
    ).join(
        User
    ).filter(
        Movie.id == movie.id,
        User.id == Comment.user_id
    ).order_by(
        Comment.addtime.desc()
    ).paginate(page=page, per_page=10)

    movie.playnum = movie.playnum + 1  # 将播放数加一
    form = CommentForm()
    if "user" in session and form.validate_on_submit():
        data = form.data
        comment = Comment(
            content = data["content"],
            movie_id = movie.id,
            user_id = session["user_id"]
        )
        db.session.add(comment)
        db.session.commit() #保存评论

        movie.commentnum = movie.commentnum + 1 #将评论量加一
        db.session.add(movie)
        db.session.commit()
        flash("添加评论成功！", "ok")
        return redirect(url_for('home.play', id=movie.id, page=1))
    db.session.add(movie)
    db.session.commit()
    return render_template("home/play.html", movie=movie, form=form, page_data=page_data)


@home.route("/moviecol/<int:page>/")
@user_login_req
def moviecol(page=None):
    """
    电影收藏
    """
    if page is None:
        page = 1
    page_data = Moviecol.query.join(
        Movie
    ).join(
        User
    ).filter(
        Movie.id == Moviecol.movie_id,
        User.id == session["user_id"]
    ).order_by(
        Moviecol.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("home/moviecol.html", page_data=page_data)


@home.route("/moviecol/add/", methods=["GET"])
@user_login_req
def moviecol_add():
    """
    添加电影收藏
    """
    uid = request.args.get("uid", "")
    mid = request.args.get("mid", "")
    moviecol = Moviecol.query.filter_by(
        user_id=int(uid),
        movie_id=int(mid)
    ).count()
    # 已收藏
    if moviecol == 1:
        data = dict(ok=0)
    # 未收藏进行收藏
    if moviecol == 0:
        moviecol = Moviecol(
            user_id=int(uid),
            movie_id=int(mid)
        )
        db.session.add(moviecol)
        db.session.commit()
        data = dict(ok=1)
    import json
    return json.dumps(data)


@home.route("/video/<int:id>/<int:page>/", methods=["GET", "POST"])
def video(id=None, page=None):
    """
    弹幕播放器(配合新建的播放页面单独测试)
    """
    movie = Movie.query.join(Tag).filter(
        Tag.id == Movie.tag_id,
        Movie.id == int(id)
    ).first_or_404()

    if page is None:
        page = 1
    page_data = Comment.query.join(
        Movie
    ).join(
        User
    ).filter(
        Movie.id == movie.id,
        User.id == Comment.user_id
    ).order_by(
        Comment.addtime.desc()
    ).paginate(page=page, per_page=10)

    movie.playnum = movie.playnum + 1
    form = CommentForm()
    if "user" in session and form.validate_on_submit():
        data = form.data
        comment = Comment(
            content=data["content"],
            movie_id=movie.id,
            user_id=session["user_id"]
        )
        db.session.add(comment)
        db.session.commit()
        movie.commentnum = movie.commentnum + 1
        db.session.add(movie)
        db.session.commit()
        flash("添加评论成功！", "ok")
        return redirect(url_for('home.video', id=movie.id, page=1))
    db.session.add(movie)
    db.session.commit()
    return render_template("home/video.html", movie=movie, form=form, page_data=page_data)


@home.route("/tm/", methods=["GET", "POST"])
def tm():
    """
    弹幕消息处理
    """
    import json
    if request.method == "GET":
        # 获取弹幕消息队列
        id = request.args.get('id')
        # 存放在redis队列中的键值
        key = "movie" + str(id)
        if rd.llen(key):
            msgs = rd.lrange(key, 0, 2999)
            res = {
                "code": 1,
                "danmaku": [json.loads(v) for v in msgs]
            }
        else:
            res = {
                "code": 1,
                "danmaku": []
            }
        resp = json.dumps(res)
    if request.method == "POST":
        # 添加弹幕
        data = json.loads(request.get_data())
        msg = {
            "__v": 0,
            "author": data["author"],
            "time": data["time"],
            "text": data["text"],
            "color": data["color"],
            "type": data['type'],
            "ip": request.remote_addr,
            "_id": datetime.datetime.now().strftime("%Y%m%d%H%M%S") + uuid.uuid4().hex,
            "player": [
                data["player"]
            ]
        }
        res = {
            "code": 1,
            "data": msg
        }
        resp = json.dumps(res)
        # 将添加的弹幕推入redis的队列中
        rd.lpush("movie" + str(data["player"]), json.dumps(msg))
    return Response(resp, mimetype='application/json')
