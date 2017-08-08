# coding:utf8
from datetime import datetime
from app import db


class User(db.Model):
    """
    会员
    """
    __tablename__ = 'user'
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    pwd = db.Column(db.String(100))
    email = db.Column(db.String(100))
    phone = db.Column(db.String(11), unique=True)
    info = db.Column(db.Text)
    image = db.Column(db.String(255), unique=True)
    add_time = db.Column(db.DateTime, index=True, default=datetime.now)
    uuid = db.Column(db.String(255), unique=True)
    user_log = db.relationship('UserLog', backref='user')  # 会员登陆日志外键关系关联
    comment = db.relationship('Comment', backref='user')  # 评论外键关系关联
    movie_collection = db.relationship('MovieCollection', backref='user')  # 收藏外键关系关联

    def __repr__(self):
        return '<User {}>'.format(self.name)

    def check_pwd(self, pwd):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.pwd, pwd)


class UserLog(db.Model):
    """
    会员登陆日志
    """
    __tablename__ = 'userlog'
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    login_ip = db.Column(db.String(100))
    login_time = db.Column(db.DateTime, index=True, default=datetime.now)

    def __repr__(self):
        return '<UserLog {}>'.format(self.id)


class Tag(db.Model):
    """
    电影标签
    """
    __tablename__ = 'tag'
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    add_time = db.Column(db.DateTime, index=True, default=datetime.now)
    movie = db.relationship('Movie', backref='tag')  # 电影外键关系关联

    def __repr__(self):
        return '<Tag {}>'.format(self.name)


class Movie(db.Model):
    """
    电影
    """
    __tablename__ = 'movie'
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), unique=True)
    url = db.Column(db.String(255), unique=True)
    info = db.Column(db.Text)
    logo = db.Column(db.String(255), unique=True)
    star = db.Column(db.SmallInteger)
    play_num = db.Column(db.BigInteger)
    comment_num = db.Column(db.BigInteger)
    area = db.Column(db.String(255))
    length = db.Column(db.String(100))
    release_time = db.Column(db.Date)  # 上映时间
    add_time = db.Column(db.DateTime, index=True, default=datetime.now)  # 添加时间
    tag_id = db.Column(db.Integer, db.ForeignKey('tag.id'))
    comment = db.relationship('Comment', backref='movie')  # 评论外键关系关联
    movie_collection = db.relationship('MovieCollection', backref='movie')  # 收藏外键关系关联

    def __repr__(self):
        return '<Movie {}>'.format(self.title)


class MoviePreview(db.Model):
    """
    电影预告
    """
    __tablename__ = 'moviepreview'
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), unique=True)
    logo = db.Column(db.String(255), unique=True)
    add_time = db.Column(db.DateTime, index=True, default=datetime.utcnow)

    def __repr__(self):
        return '<MoviePreview {}>'.format(self.title)


class Comment(db.Model):
    """
    电影评论
    """
    __tablename__ = 'comment'
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text)
    movie_id = db.Column(db.Integer, db.ForeignKey('movie.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    add_time = db.Column(db.DateTime, index=True, default=datetime.utcnow)

    def __repr__(self):
        return '<Comment {}>'.format(self.id)


class MovieCollection(db.Model):
    """
    电影收藏
    """
    __tablename__ = 'moviecollection'
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    movie_id = db.Column(db.Integer, db.ForeignKey('movie.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    add_time = db.Column(db.DateTime, index=True, default=datetime.utcnow)

    def __repr__(self):
        return '<MovieCollection {}>'.format(self.id)


class Auth(db.Model):
    """
    权限
    """
    __tablename__ = 'auth'
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    url = db.Column(db.String(255), unique=True)
    add_time = db.Column(db.DateTime, index=True, default=datetime.utcnow)

    def __repr__(self):
        return '<Auth {}>'.format(self.name)


class Role(db.Model):
    """
    角色
    """
    __tablename__ = 'role'
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    auths = db.Column(db.String(600))
    add_time = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    admin = db.relationship('Admin', backref='role')  # 管理员外键关系关联

    def __repr__(self):
        return '<Role {}>'.format(self.name)


class Admin(db.Model):
    """
    管理员
    """
    __tablename__ = 'admin'
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    pwd = db.Column(db.String(100))
    is_super = db.Column(db.SmallInteger)  # 是否是超级管理员
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))  # 所属角色
    add_time = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    adminlog = db.relationship('AdminLog', backref='admin')  # 管理员登陆日志外键关系关联
    operatelog = db.relationship('OperateLog', backref='admin')  # 操作日志外键关系关联

    def __repr__(self):
        return '<Admin {}>'.format(self.name)

    def check_pwd(self, pwd):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.pwd, pwd)


class AdminLog(db.Model):
    """
    管理员登陆日志
    """
    __tablename__ = 'adminlog'
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'))
    ip = db.Column(db.String(100))
    add_time = db.Column(db.DateTime, index=True, default=datetime.utcnow)

    def __repr__(self):
        return '<AdminLog {}>'.format(self.id)


class OperateLog(db.Model):
    """
    操作日志
    """
    __tablename__ = 'operatelog'
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'))
    ip = db.Column(db.String(100))
    reason = db.Column(db.String(600))
    add_time = db.Column(db.DateTime, index=True, default=datetime.utcnow)

    def __repr__(self):
        return '<OperateLog {}>'.format(self.id)