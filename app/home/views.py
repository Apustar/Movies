# coding:utf8
from flask import render_template, redirect, url_for, flash, session, request
from werkzeug.security import generate_password_hash
from functools import wraps
import uuid

from . import home
from .forms import RegisterForm, LoginForm
from app.models import User, UserLog
from app import db


def user_login_req(f):
    """
    登陆访问装饰器
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #  未登陆的话重定向到登陆页面
        if 'user' not in session:
            return redirect(url_for('home.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


@home.route('/')
def index():
    """"
    首页
    """
    return render_template('home/index.html')


@home.route('/login/', methods=['GET', 'POST'])
def login():
    """"
    登陆
    """
    form = LoginForm()
    if form.validate_on_submit():
        data = form.data
        user = User.query.filter_by(name=data['name']).first()
        if not user.check_pwd(data['pwd']):
            flash('密码错误', 'error')
            return redirect(url_for('home.login'))
        # 保存用户信息到session中
        session['user'] = user.name
        session['user_id'] = user.id

        # 记录会员登陆
        user_log = UserLog(
            user_id=user.id,
            login_ip=request.remote_addr
        )
        db.session.add(user_log)
        db.session.commit()
        return redirect(url_for('home.user_center'))
    return render_template('home/login.html', form=form)


@home.route('/logout/')
def logout():
    """"
    登出
    """
    session.pop('user', None)
    session.pop('user_id', None)
    return redirect(url_for('home.login'))


@home.route('/register/', methods=['GET', 'POST'])
def register():
    """"
    注册
    """
    form = RegisterForm()
    if form.validate_on_submit():
        data = form.data
        user = User(
            name=data['name'],
            email=data['email'],
            phone=data['phone'],
            pwd=generate_password_hash(data['pwd']),
            uuid=uuid.uuid4().hex
        )
        db.session.add(user)
        db.session.commit()
        flash('注册成功，请登陆', 'success')
        return redirect(url_for('home.login'))
    return render_template('home/register.html', form=form)


@home.route('/user_center/')
@user_login_req
def user_center():
    """"
    用户中心
    """
    return render_template('home/user_center.html')


@home.route('/pwd_reset/')
@user_login_req
def pwd_reset():
    """"
    密码重置
    """
    return render_template('home/pwd_reset.html')


@home.route('/my_comment/')
@user_login_req
def my_comment():
    """"
    我的评论
    """
    return render_template('home/my_comment.html')


@home.route('/login_log/')
@user_login_req
def login_log():
    """"
    我的登录日志
    """
    return render_template('home/login_log.html')


@home.route('/movie_fav/')
@user_login_req
def movie_fav():
    """"
    我收藏的电影
    """
    return render_template('home/movie_fav.html')


@home.route('/animation/')
def animation():
    """"
    首页动画
    """
    return render_template('home/animation.html')


@home.route('/search/')
def search():
    """"
    搜索
    """
    return render_template('home/search.html')


@home.route('/play/')
def play():
    """"
    播放
    """
    return render_template('home/play.html')



