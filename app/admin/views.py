# coding:utf8
from flask import render_template, url_for, redirect, flash, session, request
from functools import wraps
from werkzeug.utils import secure_filename

from app import db, app
from app.models import Admin, Tag, Movie, MoviePreview, User, Comment, \
    MovieCollection, OperateLog, UserLog, AdminLog, Auth, Role
from .forms import LoginForm, TagForm, MovieForm, MoviePreviewForm, PWDResetForm, AuthForm, RoleForm
from . import admin
import os, uuid, datetime, stat


@admin.context_processor
def tpl_extra():
    """
    上下文应用处理器，使变量能够被模板访问
    """
    data = dict(
        online_time=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )
    return data


def admin_login_req(f):
    """
    登陆访问控制
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin' not in session:
            print(url_for('admin.login', next=request.url))
            return redirect(url_for('admin.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def change_filename(filename):
    # 将文件名和后缀分离
    file_info = os.path.splitext(filename)
    # 文件名为：添加时间+uuid生成的唯一字符串+文件后缀
    filename = datetime.datetime.now().strftime('%Y%m%d%H%M%S') + str(uuid.uuid4().hex) + file_info[1]
    return filename


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
            flash('密码错误', 'error')
            return redirect(url_for('admin.login'))
        # 检测通过，则保存会话
        session['admin'] = data['account']
        session['admin_id'] = admin.id

        # 记录登陆操作
        admin_log = AdminLog(
            admin_id=admin.id,
            ip=request.remote_addr
        )
        db.session.add(admin_log)
        db.session.commit()
        return redirect(request.args.get('next') or url_for('admin.index'))
    return render_template('admin/login.html', form=form)


@admin.route('/logout/')
@admin_login_req
def logout():
    """
    后台登出
    """
    session.pop('admin', None)
    session.pop('admin_id', None)
    return redirect(url_for('admin.login'))


@admin.route('/pwd_reset/', methods=['GET', 'POST'])
@admin_login_req
def pwd_reset():
    """
    后台密码重置
    """
    form = PWDResetForm()
    if form.validate_on_submit():
        data = form.data
        admin = Admin.query.filter_by(name=session['admin']).first()
        from werkzeug.security import generate_password_hash
        admin.pwd = generate_password_hash(data['new_pwd'])
        db.session.add(admin)
        db.session.commit()
        flash('修改密码成功，请重新登陆', 'success')
        redirect(url_for('admin.logout'))
    return render_template('admin/pwd_reset.html', form=form)


@admin.route('/tag/add/', methods=['GET', 'POST'])
@admin_login_req
def tag_add():
    """
    添加标签
    """
    form = TagForm()
    if form.validate_on_submit():
        data = form.data
        tag = Tag.query.filter_by(name=data['name']).count()
        # 标签是否已经存在
        if tag == 1:
            flash('名称已经存在', 'error')
            return redirect(url_for('admin.tag_add'))
        # 将新标签加入数据库
        tag = Tag(
            name=data['name']
        )
        db.session.add(tag)
        db.session.commit()
        flash('添加标签成功', 'success')

        # 记录该操作
        oplog = OperateLog(
            admin_id=session['admin_id'],
            ip=request.remote_addr,
            reason='添加标签:{}'.format(data['name'])
        )
        db.session.add(oplog)
        db.session.commit()
        return redirect(url_for('admin.tag_add'))
    return render_template('admin/tag_add.html', form=form)


@admin.route('/tag/edit/<int:id>/', methods=['GET', 'POST'])
@admin_login_req
def tag_edit(id=None):
    """
    修改标签
    """
    form = TagForm()
    tag = Tag.query.get_or_404(id)
    if form.validate_on_submit():
        data = form.data
        tag_count = Tag.query.filter_by(name=data['name']).count()
        # 如果根据名字查到标签对象而且该名字不等于正在修改的标签的名字，则标签重复
        if tag_count == 1 and tag.name != data['name']:
            flash('名称已经存在', 'error')
            return redirect(url_for('admin.tag_edit', id=id))
        # 将修改标签更新到数据库
        tag.name = data['name']
        db.session.add(tag)
        db.session.commit()
        flash('修改标签成功', 'success')
        return redirect(url_for('admin.tag_edit', id=id))
    return render_template('admin/tag_edit.html', form=form, tag=tag)


@admin.route('/tag/delete/<int:id>/', methods=['GET'])
@admin_login_req
def tag_del(id=None):
    """
    标签删除
    """
    tag = Tag.query.filter_by(id=id).first_or_404()
    db.session.delete(tag)
    db.session.commit()
    flash('删除标签成功', 'success')
    return redirect(url_for('admin.tag_list', page=1))


@admin.route('/tag/list/<int:page>/', methods=['GET'])
@admin_login_req
def tag_list(page=None):
    """
    标签列表
    """
    if page is None:
        page = 1
    data = Tag.query.order_by(
        Tag.add_time.desc()
    ).paginate(page=page, per_page=10)
    return render_template('admin/tag_list.html', data=data)


@admin.route('/movie/add/', methods=['GET', 'POST'])
@admin_login_req
def movie_add():
    """
    添加电影
    """
    form = MovieForm()
    form.tag_id.choices = [(v.id, v.name) for v in Tag.query.all()]
    if form.validate_on_submit():

        data = form.data
        file_url = secure_filename(form.url.data.filename)
        file_logo = secure_filename(form.logo.data.filename)

        # 保存路径是否存在
        if not os.path.exists(app.config['UP_DIR']):
            os.makedirs(app.config['UP_DIR'])
            os.chmod(app.config['UP_DIR'], stat.S_IRWXU)

        # 生成唯一文件名
        url = change_filename(file_url)
        logo = change_filename(file_logo)

        # 保存文件
        form.url.data.save(app.config['UP_DIR'] + url)
        form.logo.data.save(app.config['UP_DIR'] + logo)

        # 构造电影实体，存入数据库
        movie = Movie(
            title=data['title'],
            url=url,
            info=data['info'],
            logo=logo,
            star=int(data['star']),
            play_num=0,
            comment_num=0,
            tag_id=int(data['tag_id']),
            area=data['area'],
            release_time=data['release_time'],
            length=data['length']
        )
        db.session.add(movie)
        db.session.commit()
        flash('添加电影成功', 'success')
        return redirect(url_for('admin.movie_add'))
    return render_template('admin/movie_add.html', form=form)


@admin.route('/movie/list/<int:page>/', methods=['GET'])
@admin_login_req
def movie_list(page=None):
    """
    电影列表
    """
    if page is None:
        page = 1
    # 使用join联合查询Tag和movie表
    data = Movie.query.join(Tag).filter(
        Tag.id == Movie.tag_id
    ).order_by(
        Movie.add_time.desc()
    ).paginate(page=page, per_page=2)
    return render_template('admin/movie_list.html', data=data)


@admin.route('/movie/edit/<int:id>/', methods=['GET', 'POST'])
@admin_login_req
def movie_edit(id=None):
    """
    编辑电影
    """
    form = MovieForm()
    # 电影的logo和url已经存在，不用进行验证
    form.url.validators = []
    form.logo.validators = []
    movie = Movie.query.get_or_404(int(id))

    # 赋初值(因为部分字段在html里不容易获取值)
    if request.method == 'GET':
        form.info.data = movie.info
        form.tag_id.data = movie.tag_id
        form.star.data = movie.star

    if form.validate_on_submit():
        data = form.data

        # 片名不能重复
        movie_count = Movie.query.filter_by(title=data['title']).count()
        if movie_count == 1 and movie.title != data['title']:
            flash('片名不能重复', 'error')
            return redirect(url_for('admin.movie_edit', id=id))

        # 保存路径是否存在
        if not os.path.exists(app.config['UP_DIR']):
            os.makedirs(app.config['UP_DIR'])
            os.chmod(app.config['UP_DIR'], stat.S_IRWXU)

        # 生成唯一文件名并保存
        if form.url.data.filename != '':
            file_url = secure_filename(form.url.data.filename)
            movie.url = change_filename(file_url)
            form.url.data.save(app.config['UP_DIR'] + movie.url)
        if form.logo.data.filename != '':
            file_logo = secure_filename(form.logo.data.filename)
            movie.logo = change_filename(file_logo)
            form.logo.data.save(app.config['UP_DIR'] + movie.logo)

        # 获取其他修改的信息并保存到数据库
        movie.star = data['star']
        movie.tag_id = data['tag_id']
        movie.info = data['info']
        movie.title = data['title']
        movie.area = data['area']
        movie.length = data['length']
        movie.release_time = data['release_time']
        db.session.add(movie)
        db.session.commit()
        flash('编辑电影成功', 'success')
        return redirect(url_for('admin.movie_edit', id=id))
    return render_template('admin/movie_edit.html', form=form, movie=movie)


@admin.route('/movie/del/<int:id>/', methods=['GET'])
@admin_login_req
def movie_del(id=None):
    """
    删除电影
    """
    movie = Movie.query.get_or_404(int(id))
    db.session.delete(movie)
    db.session.commit()
    flash('删除电影成功', 'success')
    return redirect(url_for('admin.movie_list', page=1))


@admin.route('/movie_pre/add/', methods=['GET', 'POST'])
@admin_login_req
def movie_pre_add():
    """
    添加电影预告
    """
    form = MoviePreviewForm()
    if form.validate_on_submit():
        data = form.data

        file_logo = secure_filename(form.logo.data.filename)

        # 保存路径是否存在
        if not os.path.exists(app.config['UP_DIR']):
            os.makedirs(app.config['UP_DIR'])
            os.chmod(app.config['UP_DIR'], stat.S_IRWXU)
        # 生成唯一文件名
        logo = change_filename(file_logo)
        # 保存文件
        form.logo.data.save(app.config['UP_DIR'] + logo)
        movie_pre = MoviePreview(
            title=data['title'],
            logo=logo
        )
        db.session.add(movie_pre)
        db.session.commit()
        flash('添加预告成功', 'success')
        return redirect(url_for('admin.movie_pre_add'))
    return render_template('admin/movie_pre_add.html', form=form)


@admin.route('/movie_pre/edit/<int:id>/', methods=['GET', 'POST'])
@admin_login_req
def movie_pre_edit(id=None):
    """
    编辑电影预告
    """
    form = MoviePreviewForm()
    # 电影的logo和url已经存在，不用进行验证
    form.logo.validators = []
    movie_pre = MoviePreview.query.get_or_404(int(id))

    if form.validate_on_submit():
        data = form.data

        # 片名不能重复
        movie_pre_count = MoviePreview.query.filter_by(title=data['title']).count()
        if movie_pre_count == 1 and movie_pre.title != data['title']:
            flash('预告片名不能重复', 'error')
            return redirect(url_for('admin.movie_pre_edit', id=id))

        # 保存路径是否存在
        if not os.path.exists(app.config['UP_DIR']):
            os.makedirs(app.config['UP_DIR'])
            os.chmod(app.config['UP_DIR'], stat.S_IRWXU)

        # 生成唯一文件名并保存
        if form.logo.data.filename != '':
            file_logo = secure_filename(form.logo.data.filename)
            movie_pre.logo = change_filename(file_logo)
            form.logo.data.save(app.config['UP_DIR'] + movie_pre.logo)

        # 获取其他修改的信息并保存到数据库
        movie_pre.title = data['title']
        db.session.add(movie_pre)
        db.session.commit()
        flash('编辑电影预告成功', 'success')
        return redirect(url_for('admin.movie_pre_edit', id=id))
    return render_template('admin/movie_pre_edit.html', form=form, movie_pre=movie_pre)


@admin.route('/movie_pre/list/<int:page>/', methods=['GET'])
@admin_login_req
def movie_pre_list(page=None):
    """
    电影预告列表
    """
    if page is None:
        page = 1
    data = MoviePreview.query.order_by(
        MoviePreview.add_time.desc()
    ).paginate(page=page, per_page=2)
    return render_template('admin/movie_pre_list.html', data=data)


@admin.route('/movie_pre/del/<int:id>/', methods=['GET'])
@admin_login_req
def movie_pre_del(id=None):
    """
    删除电影预告
    """
    movie_pre = MoviePreview.query.get_or_404(int(id))
    db.session.delete(movie_pre)
    db.session.commit()
    flash('删除电影预告成功', 'success')
    return redirect(url_for('admin.movie_pre_list', page=1))


@admin.route('/user/list/<int:page>/', methods=['GET'])
@admin_login_req
def user_list(page=None):
    """
    会员列表
    """
    if page is None:
        page = 1
    data = User.query.order_by(
        User.add_time.desc()
    ).paginate(page=page, per_page=2)
    return render_template('admin/user_list.html', data=data)


@admin.route('/user/detail/<int:id>/', methods=['GET'])
@admin_login_req
def user_detail(id=None):
    """
    会员详细信息
    """
    user = User.query.get_or_404(int(id))
    return render_template('admin/user_detail.html', user=user)


@admin.route('/user/del/<int:id>/', methods=['GET'])
@admin_login_req
def user_del(id=None):
    """
    删除会员
    """
    user = User.query.get_or_404(int(id))
    db.session.delete(user)
    db.session.commit()
    flash('删除会员成功', 'success')
    return redirect(url_for('admin.user_list', page=1))


@admin.route('/comment/list/<int:page>/', methods=['GET'])
@admin_login_req
def comment_list(page=None):
    """
    评论列表
    """
    if page is None:
        page = 1
    # 关联Movie和User表
    data = Comment.query.join(Movie).join(User).filter(
        Movie.id == Comment.movie_id,
        User.id == Comment.user_id,
    ).order_by(
        Comment.add_time.desc()
    ).paginate(page=page, per_page=2)
    return render_template('admin/comment_list.html', data=data)


@admin.route('/comment/del/<int:id>/', methods=['GET'])
@admin_login_req
def comment_del(id=None):
    """
    删除评论
    """
    comment = Comment.query.get_or_404(int(id))
    db.session.delete(comment)
    db.session.commit()
    flash('删除评论成功', 'success')
    return redirect(url_for('admin.comment_list', page=1))


@admin.route('/movie/collist/<int:page>/', methods=['GET'])
@admin_login_req
def movie_collist(page=None):
    """
    电影收藏
    """
    if page is None:
        page = 1
    # 关联Movie和User表
    data = MovieCollection.query.join(Movie).join(User).filter(
        Movie.id == MovieCollection.movie_id,
        User.id == MovieCollection.user_id,
    ).order_by(
        MovieCollection.add_time.desc()
    ).paginate(page=page, per_page=2)
    return render_template('admin/movie_collist.html', data=data)


@admin.route('/movie/collist/del/<int:id>/', methods=['GET'])
@admin_login_req
def movie_col_del(id=None):
    """
    删除收藏
    """
    movie_col = MovieCollection.query.get_or_404(int(id))
    db.session.delete(movie_col)
    db.session.commit()
    flash('删除收藏成功', 'success')
    return redirect(url_for('admin.movie_collist', page=1))


@admin.route('/oplog/list/<int:page>/', methods=['GET'])
@admin_login_req
def oplog_list(page=None):
    """
    操作日志列表
    """
    if page is None:
        page = 1
    # 关联Admin表
    data = OperateLog.query.join(Admin).filter(
        OperateLog.admin_id == Admin.id
    ).order_by(
        OperateLog.add_time.desc()
    ).paginate(page=page, per_page=2)
    return render_template('admin/oplog_list.html', data=data)


@admin.route('/adminloginlog/list/<int:page>/', methods=['GET'])
@admin_login_req
def adminloginlog_list(page=None):
    """
    管理员登陆日志列表
    """
    if page is None:
        page = 1
    # 关联Admin表
    data = AdminLog.query.join(Admin).filter(
        AdminLog.admin_id == Admin.id
    ).order_by(
        AdminLog.add_time.desc()
    ).paginate(page=page, per_page=2)
    return render_template('admin/adminloginlog_list.html', data=data)


@admin.route('/userloginlog/list/<int:page>/', methods=['GET'])
@admin_login_req
def userloginlog_list(page=None):
    """
    用户登陆日志列表
    """
    if page is None:
        page = 1
    # 关联Admin表
    data = UserLog.query.join(User).filter(
        UserLog.admin_id == User.id
    ).order_by(
        UserLog.add_time.desc()
    ).paginate(page=page, per_page=2)
    return render_template('admin/userloginlog_list.html', data=data)


@admin.route('/role/add/', methods=['GET', 'POST'])
@admin_login_req
def role_add():
    """
     添加角色
     """
    form = RoleForm()
    if form.validate_on_submit():
        data = form.data
        role = Role(
            name=data['name'],
            # 使用join拼接权限数组,先转化为字符串,因为权限ID是int
            auths=','.join([str(auth) for auth in data['auths']])
        )
        db.session.add(role)
        db.session.commit()
        flash('角色添加成功', 'success')
    return render_template('admin/role_add.html', form=form)


@admin.route('/role/edit/<int:id>/', methods=['GET', 'POST'])
@admin_login_req
def role_edit(id=None):
    """
    修改角色
    """
    form = RoleForm()
    role = Role.query.get_or_404(id)

    # 对权限列表赋予初值,先对数据进行处理，转化成int型的列表
    if request.method == 'GET':
        form.auths.data = [int(auth) for auth in role.auths.split(',')]

    if form.validate_on_submit():
        data = form.data
        # 将修改权限更新到数据库
        role.name = data['name']
        role.auths = ','.join([str(auth) for auth in data['auths']])
        db.session.add(role)
        db.session.commit()
        flash('修改权限成功', 'success')
        return redirect(url_for('admin.auth_edit', id=id))
    return render_template('admin/role_edit.html', form=form, role=role)


@admin.route('/role/delete/<int:id>/', methods=['GET'])
@admin_login_req
def role_del(id=None):
    """
    角色删除
    """
    role = Role.query.filter_by(id=id).first_or_404()
    db.session.delete(role)
    db.session.commit()
    flash('删除角色成功', 'success')
    return redirect(url_for('admin.role_list', page=1))


@admin.route('/role/list/<int:page>/', methods=['GET'])
@admin_login_req
def role_list(page=None):
    """
    角色列表
    """
    if page is None:
        page = 1
    data = Role.query.order_by(
        Role.add_time.desc()
    ).paginate(page=page, per_page=5)
    return render_template('admin/role_list.html', data=data)


@admin.route('/auth/add/', methods=['GET', 'POST'])
@admin_login_req
def auth_add():
    """
    添加权限
    """
    form = AuthForm()
    if form.validate_on_submit():
        data = form.data

        auth_count = Auth.query.filter_by(url=data['url']).count()
        # 标签是否已经存在
        if auth_count == 1:
            flash('该权限已经存在', 'error')
            return redirect(url_for('admin.auth_add'))

        auth = Auth(
            name=data['name'],
            url=data['url']
        )
        db.session.add(auth)
        db.session.commit()
        flash('权限添加成功', 'success')
        return redirect(url_for('admin.auth_add'))
    return render_template('admin/auth_add.html', form=form)


@admin.route('/auth/edit/<int:id>/', methods=['GET', 'POST'])
@admin_login_req
def auth_edit(id=None):
    """
    修改权限
    """
    form = AuthForm()
    auth = Auth.query.get_or_404(id)
    if form.validate_on_submit():
        data = form.data
        auth_count = Auth.query.filter_by(url=data['url']).count()
        # 如果根据名字查到权限对象而且该url不等于正在修改的权限的url，则权限重复
        if auth_count == 1 and auth.url != data['url']:
            flash('权限已经存在', 'error')
            return redirect(url_for('admin.auth_edit', id=id))
        # 将修改权限更新到数据库
        auth.name = data['name']
        auth.url = data['url']
        db.session.add(auth)
        db.session.commit()
        flash('修改权限成功', 'success')
        return redirect(url_for('admin.auth_edit', id=id))
    return render_template('admin/auth_edit.html', form=form, auth=auth)


@admin.route('/auth/delete/<int:id>/', methods=['GET'])
@admin_login_req
def auth_del(id=None):
    """
    权限删除
    """
    auth = Auth.query.filter_by(id=id).first_or_404()
    db.session.delete(auth)
    db.session.commit()
    flash('删除权限成功', 'success')
    return redirect(url_for('admin.auth_list', page=1))


@admin.route('/auth/list/<int:page>/', methods=['GET'])
@admin_login_req
def auth_list(page=None):
    """
     权限列表
     """
    if page is None:
        page = 1
    data = Auth.query.order_by(
        Auth.add_time.desc()
    ).paginate(page=page, per_page=5)
    return render_template('admin/auth_list.html', data=data)


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
