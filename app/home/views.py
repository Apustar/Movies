# coding:utf8
from . import home
from flask import render_template, redirect, url_for


@home.route('/')
def index():
    """"
    首页
    """
    return render_template('home/index.html')


@home.route('/login/')
def login():
    """"
    登陆
    """
    return render_template('home/login.html')


@home.route('/logout/')
def logout():
    """"
    登出
    """
    return redirect(url_for('home.login'))


@home.route('/register/')
def register():
    """"
    注册
    """
    return render_template('home/register.html')


@home.route('/user_center/')
def user_center():
    """"
    用户中心
    """
    return render_template('home/user_center.html')


@home.route('/pwd_reset/')
def pwd_reset():
    """"
    密码重置
    """
    return render_template('home/pwd_reset.html')


@home.route('/my_comment/')
def my_comment():
    """"
    我的评论
    """
    return render_template('home/my_comment.html')


@home.route('/login_log/')
def login_log():
    """"
    我的登录日志
    """
    return render_template('home/login_log.html')


@home.route('/movie_fav/')
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



