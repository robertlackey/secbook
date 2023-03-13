from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_security import UserMixin, RoleMixin, SQLAlchemyUserDatastore
from flask_login import LoginManager
# from sqlalchemy_continuum import make_versioned, version_class, parent_class
# import sqlalchemy as sa
# from sqlalchemy_continuum.plugins import FlaskPlugin

login_manager = LoginManager()

# db = SQLAlchemy(session_options={"autoflush": False})
db = SQLAlchemy()

# make_versioned(user_cls=None, plugins=[FlaskPlugin()])
# sa.orm.configure_mappers()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#database class to store playbook data
class Playbook(db.Model):
    __bind_key__ = "playbook"
    __versioned__ = {}
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(200), default=" ")
    update_user = db.Column(db.String(500), default=" ")
    play_name = db.Column(db.String(200), nullable=False)
    playbook_description = db.Column(db.String(500), default=" ")
    playbook_owner = db.Column(db.String(200), default="")
    severity = db.Column(db.String(500), default=" ")
    playbook_status = db.Column(db.String(200), default=" ")
    date_added = db.Column(db.DateTime, default=datetime.utcnow())
    date_updated = db.Column(db.DateTime)
    mitre_tactic = db.Column(db.String(300), default=" ")
    mitre_id = db.Column(db.String(200), default=" ")
    mitre_os = db.Column(db.String(500), default=" ")
    deleted = db.Column(db.Integer, default=0)

    #mitre data tables to be stored after pulled from mitre github
    mitre_info_url = db.Column(db.String(), default=" ")
    mitre_info_platforms = db.Column(db.String(), default=" ")
    mitre_info_tactic = db.Column(db.String(), default=" ")
    mitre_info_subtechnique = db.Column(db.String(), default=" ")
    mitre_info_subtechnique_url = db.Column(db.String(), default=" ")

    def __repr__(self):
        return f"Playbook('{self.id}')"

# sa.orm.configure_mappers()
# PlaybookVersion = version_class(Playbook)
# parent_class(version_class(Playbook))

# Define models for User and Role
roles_users = db.Table('roles_users',
                       db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
                       db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
                       )

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)