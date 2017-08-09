# coding:utf8
from flask import render_template, redirect, url_for, flash, session, request
from werkzeug.security import generate_password_hash
from functools import wraps
from werkzeug.utils import secure_filename
import uuid
import os
import datetime
import stat
import json

from . import home
from .forms import RegisterForm, LoginForm, UserDetailForm, PWDResetForm, CommentForm
from app.models import User, UserLog, MoviePreview, Tag, Movie, Comment, MovieCollection
from app import db, app


def change_filename(filename):
    """
    生成一个唯一的文件名
    """
    # 将文件名和后缀分离
    file_info = os.path.splitext(filename)
    # 文件名为：添加时间+uuid生成的唯一字符串+文件后缀
    filename = datetime.datetime.now().strftime('%Y%m%d%H%M%S') + str(uuid.uuid4().hex) + file_info[1]
    return filename


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


@home.route('/<int:page>/', methods=['GET'])
def index(page=None):
    """"
    首页
    """
    tags = Tag.query.all()
    tag_id = request.args.get('tag_id', 0)
    star = request.args.get('star', 0)
    time = request.args.get('time', 0)
    pm = request.args.get('pm', 0)
    cm = request.args.get('cm', 0)

    data = Movie.query
    if int(tag_id) != 0:
        # 按照tag筛选
        data = data.filter_by(tag_id=tag_id)

    if int(star) != 0:
        # 按照星级筛选
        data = data.filter_by(star=int(star))

    if int(time) != 0:
        if int(time) == 1:  # 时间早到晚
            data = data.order_by(Movie.add_time.desc())
        if int(time) == 2:  # 时间晚到早
            data = data.order_by(Movie.add_time.asc())

    if int(pm) != 0:
        if int(pm) == 1:  # 播放量高到低
            data = data.order_by(Movie.play_num.desc())
        if int(pm) == 2:  # 播放量低到高
            data = data.order_by(Movie.play_num.asc())

    if int(cm) != 0:
        if int(cm) == 1:  # 评论量高到低
            data = data.order_by(Movie.comment_num.desc())
        if int(cm) == 2:  # 评论量低到高
            data = data.order_by(Movie.comment_num.asc())

    if page is None:
        page = 1
    data = data.paginate(page=page, per_page=8)
    p = dict(
        tag_id=tag_id,
        star=star,
        time=time,
        pm=pm,
        cm=cm
    )
    return render_template('home/index.html', tags=tags, p=p, data=data)


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


@home.route('/user_center/', methods=['GET', 'POST'])
@user_login_req
def user_center():
    """"
    用户中心
    """
    form = UserDetailForm()
    form.image.validators = []
    user = User.query.get(int(session['user_id']))

    # 赋值
    if request.method == 'GET':
        form.name.data = user.name
        form.email.data = user.email
        form.phone.data = user.phone
        form.info.data = user.info

    if form.validate_on_submit():
        data = form.data
        print(form.image.data)
        # 保存头像
        file_image = secure_filename(form.image.data.filename)
        if not os.path.exists(app.config['USER_IMAGE_DIR']):
            os.makedirs(app.config['USER_IMAGE_DIR'])
            os.chmod(app.config['USER_IMAGE_DIR'], stat.S_IRWXU)
        user.image = change_filename(file_image)
        form.image.data.save(app.config['USER_IMAGE_DIR'] + user.image)

        # 剩余信息录入
        user.name = data['name']
        user.email = data['email']
        user.phone = data['phone']
        user.info = data['info']
        db.session.add(user)
        db.session.commit()
        flash('修改成功', 'success')
        return redirect(url_for('home.user_center'))
    return render_template('home/user_center.html', form=form, user=user)


@home.route('/pwd_reset/', methods=['GET', 'POST'])
@user_login_req
def pwd_reset():
    """"
    密码重置
    """
    form = PWDResetForm()
    if form.validate_on_submit():
        data = form.data
        user = User.query.filter_by(name=session['user']).first()

        if not user.check_pwd(data['old_pwd']):
            flash('旧密码错误', 'error')
            return redirect(url_for('home.pwd_reset'))
        user.pwd = generate_password_hash(data['new_pwd'])
        db.session.add(user)
        db.session.commit()
        flash('修改密码成功，请重新登陆', 'success')
        return redirect(url_for('home.logout'))
    return render_template('home/pwd_reset.html', form=form)


@home.route('/my_comment/<int:page>/')
@user_login_req
def my_comment(page=None):
    """"
    我的评论
    """
    if page is None:
        page = 1
    data = Comment.query.join(Movie).filter(
        Comment.movie_id == Movie.id,
        Comment.user_id == session['user_id']
    ).order_by(Comment.add_time.desc()).paginate(page=page, per_page=3)
    return render_template('home/my_comment.html', data=data)


@home.route('/login_log/<int:page>/', methods=['GET'])
@user_login_req
def login_log(page=None):
    """"
    我的登录日志
    """
    if page is None:
        page = 1
    # 关联User表
    data = UserLog.query.filter_by(
        user_id=int(session['user_id'])
    ).order_by(
        UserLog.login_time.desc()
    ).paginate(page=page, per_page=2)
    return render_template('home/login_log.html', data=data)


@home.route('/movie_fav/add/', methods=['GET', 'POST'])
@user_login_req
def movie_fav():
    """"
    收藏电影
    """
    user_id = request.args.get('user_id', '')
    movie_id = request.args.get('movie_id', '')
    movie_col_count = MovieCollection.query.filter_by(
        user_id=int(user_id),
        movie_id=int(movie_id)
    ).count()

    if movie_col_count == 1:  # 已收藏，进行取消收藏操作
        movie_col = MovieCollection.query.filter_by(
            user_id=int(user_id),
            movie_id=int(movie_id)
        ).first_or_404()
        db.session.delete(movie_col)
        db.session.commit()
        data = dict(ok=0)

    if movie_col_count == 0:  # 未收藏, 进行收藏操作
        movie_col = MovieCollection(
            user_id=int(user_id),
            movie_id=int(movie_id)
        )
        db.session.add(movie_col)
        db.session.commit()
        data = dict(ok=1)
    return json.dumps(data)


@home.route('/movie_col_list/<int:page>/', methods=['GET'])
@user_login_req
def movie_col_list(page=None):
    if page is None:
        page = 1

    data = MovieCollection.query.join(Movie).join(User).filter(
        User.id == session['user_id'],
        Movie.id == MovieCollection.movie_id
    ).order_by(MovieCollection.add_time.desc()).paginate(page=page, per_page=4)

    return render_template('home/movie_col_list.html', data=data)


@home.route('/animation/')
def animation():
    """"
    首页动画
    """
    data = MoviePreview.query.all()
    return render_template('home/animation.html', data=data)


@home.route('/search/<int:page>/', methods=['GET'])
def search(page=None):
    """"
    搜索
    """
    key = request.args.get('key', '')

    movie_count = Movie.query.filter(
        Movie.title.ilike('%' + key + '%')
    ).count()

    data = Movie.query.filter(
        Movie.title.ilike('%' + key + '%')
    ).order_by(
        Movie.add_time.desc()
    ).paginate(page=page, per_page=4)
    return render_template('home/search.html', key=key, data=data, movie_count=movie_count)


@home.route('/play/<int:id>/<int:page>/', methods=['GET', 'POST'])
def play(id=None, page=None):
    """"
    播放
    """
    # 电影是否被收藏标志
    has_fav = False

    count = MovieCollection.query.filter_by(
        user_id=session['user_id'],
        movie_id=int(id)
    ).count()

    # 判断该电影时候已被收藏
    if count == 0:
        has_fav = False
    else:
        has_fav = True

    form = CommentForm()

    # 电影实体
    movie = Movie.query.join(Tag).filter(
        Tag.id == Movie.tag_id,
        Movie.id == int(id)
    ).first_or_404()

    # 电影评论
    if page is None:
        page = 1
    # 关联Movie和User表
    data = Comment.query.join(Movie).join(User).filter(
        Movie.id == movie.id,
        User.id == Comment.user_id,
    ).order_by(
        Comment.add_time.desc()
    ).paginate(page=page, per_page=4)

    # 点进来播放量+1
    movie.play_num += 1

    # 评论提交
    if 'user' in session and form.validate_on_submit():
        data = form.data
        comment = Comment(
            content=data['content'],
            movie_id=int(id),
            user_id=session['user_id']
        )

        db.session.add(comment)
        db.session.commit()
        # 评论提交成功评论量+1
        movie.comment_num += 1
        db.session.add(movie)
        db.session.commit()
        flash('添加评论成功', 'success')
        return redirect(url_for('home.play', id=movie.id, page=1))

    db.session.add(movie)
    db.session.commit()

    return render_template('home/play.html', movie=movie, form=form, data=data, has_fav=has_fav)



