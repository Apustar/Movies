# coding:utf8
from . import admin
from flask import render_template, url_for, redirect, flash, session, request
from .forms import LoginForm
from app.models import Admin
from functools import wraps


def admin_login_req(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin' not in session:
            print(url_for('admin.login', next=request.url))
            return redirect(url_for('admin.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


@admin.route('/')
@admin_login_req
def index():
    """
    后台首页
    """
    return render_template('admin/index.html')


@admin.route('/login/', methods=['GET', 'POST'])
def login():
    """
    后台登录
    """
    form = LoginForm()
    if form.validate_on_submit():
        data = form.data
        admin = Admin.query.filter_by(name=data['account']).first()
        if not admin.check_pwd(data['pwd']):
            # 错误消息闪现
            flash('密码错误')
            return redirect(url_for('admin.login'))
        # 检测通过，则保存会话
        session['admin'] = data['account']
        return redirect(request.args.get('next') or url_for('admin.index'))
    return render_template('admin/login.html', form=form)


@admin.route('/logout/')
@admin_login_req
def logout():
    """
    后台登出
    """
    session.pop('admin', None)
    return redirect(url_for('admin.login'))


@admin.route('/pwd_reset/')
@admin_login_req
def pwd_reset():
    """
    后台密码重置
    """
    return render_template('admin/pwd_reset.html')


@admin.route('/tag/add/')
@admin_login_req
def tag_add():
    """
    添加标签
    """
    return render_template('admin/tag_add.html')


@admin.route('/tag/list/')
@admin_login_req
def tag_list():
    """
    标签列表
    """
    return render_template('admin/tag_list.html')


@admin.route('/movie/add/')
@admin_login_req
def movie_add():
    """
    添加电影
    """
    return render_template('admin/movie_add.html')


@admin.route('/movie/list/')
@admin_login_req
def movie_list():
    """
    电影列表
    """
    return render_template('admin/movie_list.html')


@admin.route('/movie_pre/add/')
@admin_login_req
def movie_pre_add():
    """
    添加电影预告
    """
    return render_template('admin/movie_pre_add.html')


@admin.route('/movie_pre/list/')
@admin_login_req
def movie_pre_list():
    """
    电影预告列表
    """
    return render_template('admin/movie_pre_list.html')


@admin.route('/user/list/')
@admin_login_req
def user_list():
    """
    会员列表
    """
    return render_template('admin/user_list.html')


@admin.route('/user/detail/')
@admin_login_req
def user_detail():
    """
    会员详细信息
    """
    return render_template('admin/user_detail.html')


@admin.route('/comment/list/')
@admin_login_req
def comment_list():
    """
    评论列表
    """
    return render_template('admin/comment_list.html')


@admin.route('/movie/collist/')
@admin_login_req
def movie_collist():
    """
    电影收藏
    """
    return render_template('admin/movie_collist.html')


@admin.route('/oplog/list/')
@admin_login_req
def oplog_list():
    """
    操作登陆日志列表
    """
    return render_template('admin/oplog_list.html')


@admin.route('/adminloginlog/list/')
@admin_login_req
def adminloginlog_list():
    """
    管理员登陆日志列表
    """
    return render_template('admin/adminloginlog_list.html')


@admin.route('/userloginlog/list/')
@admin_login_req
def userloginlog_list():
    """
    用户登陆日志列表
    """
    return render_template('admin/userloginlog_list.html')


@admin.route('/role/add/')
@admin_login_req
def role_add():
    """
     添加角色
     """
    return render_template('admin/role_add.html')


@admin.route('/role/list/')
@admin_login_req
def role_list():
    """
    角色列表
    """
    return render_template('admin/role_list.html')


@admin.route('/auth/add/')
@admin_login_req
def auth_add():
    """
    添加权限
    """
    return render_template('admin/auth_add.html')


@admin.route('/auth/list/')
@admin_login_req
def auth_list():
    """
     权限列表
     """
    return render_template('admin/auth_list.html')


@admin.route('/admin/add/')
@admin_login_req
def admin_add():
    """
     添加管理员
     """
    return render_template('admin/admin_add.html')


@admin.route('/admin/list/')
@admin_login_req
def admin_list():
    """
     管理员列表
     """
    return render_template('admin/admin_list.html')
