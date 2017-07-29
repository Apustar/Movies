# coding:utf8
from . import admin
from flask import render_template, url_for, redirect


@admin.route('/')
def index():
    """
    后台首页
    """
    return render_template('admin/index.html')


@admin.route('/login/')
def login():
    """
    后台登录
    """
    return render_template('admin/login.html')


@admin.route('/logout/')
def logout():
    """
    后台登出
    """
    return redirect(url_for('admin.login'))


@admin.route('/pwd_reset/')
def pwd_reset():
    """
    后台密码重置
    """
    return render_template('admin/pwd_reset.html')


@admin.route('/tag/add/')
def tag_add():
    """
    添加标签
    """
    return render_template('admin/tag_add.html')


@admin.route('/tag/list/')
def tag_list():
    """
    标签列表
    """
    return render_template('admin/tag_list.html')


@admin.route('/movie/add/')
def movie_add():
    """
    添加电影
    """
    return render_template('admin/movie_add.html')


@admin.route('/movie/list/')
def movie_list():
    """
    电影列表
    """
    return render_template('admin/movie_list.html')


@admin.route('/movie_pre/add/')
def movie_pre_add():
    """
    添加电影预告
    """
    return render_template('admin/movie_pre_add.html')


@admin.route('/movie_pre/list/')
def movie_pre_list():
    """
    电影预告列表
    """
    return render_template('admin/movie_pre_list.html')


@admin.route('/user/list/')
def user_list():
    """
    会员列表
    """
    return render_template('admin/user_list.html')


@admin.route('/user/detail/')
def user_detail():
    """
    会员详细信息
    """
    return render_template('admin/user_detail.html')


@admin.route('/comment/list/')
def comment_list():
    """
    评论列表
    """
    return render_template('admin/comment_list.html')


@admin.route('/movie/collist/')
def movie_collist():
    """
    电影收藏
    """
    return render_template('admin/movie_collist.html')


@admin.route('/oplog/list/')
def oplog_list():
    """
    操作登陆日志列表
    """
    return render_template('admin/oplog_list.html')


@admin.route('/adminloginlog/list/')
def adminloginlog_list():
    """
    管理员登陆日志列表
    """
    return render_template('admin/adminloginlog_list.html')


@admin.route('/userloginlog/list/')
def userloginlog_list():
    """
    用户登陆日志列表
    """
    return render_template('admin/userloginlog_list.html')


@admin.route('/role/add/')
def role_add():
    """
     添加角色
     """
    return render_template('admin/role_add.html')


@admin.route('/role/list/')
def role_list():
    """
    角色列表
    """
    return render_template('admin/role_list.html')


@admin.route('/auth/add/')
def auth_add():
    """
    添加权限
    """
    return render_template('admin/auth_add.html')


@admin.route('/auth/list/')
def auth_list():
    """
     权限列表
     """
    return render_template('admin/auth_list.html')


@admin.route('/admin/add/')
def admin_add():
    """
     添加管理员
     """
    return render_template('admin/admin_add.html')


@admin.route('/admin/list/')
def admin_list():
    """
     管理员列表
     """
    return render_template('admin/admin_list.html')
