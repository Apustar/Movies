# coding:utf8
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import pymysql

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:ssjusher123@localhost:3306/movie?charset=utf8'
# app.config['SQLAlCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY'] = '2b7d6a6c8dad45da855f1c63d4a40c88'
app.debug = True
db = SQLAlchemy(app)

from app.home import home as home_blueprint
from app.admin import admin as admin_blueprint

app.register_blueprint(home_blueprint)
app.register_blueprint(admin_blueprint, url_prefix='/admin')