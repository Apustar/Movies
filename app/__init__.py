# coding:utf8
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
import pymysql, os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:ssjusher123@localhost:3306/movie?charset=utf8'
# app.config['SQLAlCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY'] = '2b7d6a6c8dad45da855f1c63d4a40c88'
app.config['UP_DIR'] = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static/uploads/')
app.config['USER_IMAGE_DIR'] = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static/uploads/users/')
app.debug = True
db = SQLAlchemy(app)

from app.home import home as home_blueprint
from app.admin import admin as admin_blueprint

app.register_blueprint(home_blueprint)
app.register_blueprint(admin_blueprint, url_prefix='/admin')


@app.errorhandler(404)
def page_not_found(error):
    """
    404页面
    """
    return render_template('home/404.html'), 404
