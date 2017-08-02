from app import db
from app.models import Role, Admin

if __name__ == '__main__':
    db.create_all()
    role = Role(
        name='超级管理员',
        auths=''
    )
    db.session.add(role)
    db.session.commit()
    from werkzeug.security import generate_password_hash

    admin = Admin(
        name='SSJ',
        pwd=generate_password_hash('123456'),
        is_super=0,
        role_id=1
    )
    db.session.add(admin)
    db.session.commit()