import os
from playbook import db, app
from models import User, Role
from flask_bcrypt import generate_password_hash
import psycopg2
from psycopg2.extensions import AsIs

# List of databases to create
databases = ['playbook', 'user', 'users']

# Loop through databases and create if they don't exist
for database in databases:
    conn = psycopg2.connect(
        host=os.environ.get('POSTGRES_URL'),
        port=5432,
        user=os.environ.get('POSTGRES_USER'),
        password=os.environ.get('POSTGRES_PASSWORD'),
        database="playbook"
    )
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM pg_database WHERE datname=%s", (database,))
    exists = cur.fetchone()
    if not exists:
        cur.execute('CREATE DATABASE "%s";', (AsIs(database),))
    cur.close()
    conn.close()

app_info = {
    'APP_USER' : os.environ.get('APP_USER'),
    'APP_PASSWORD': os.environ.get('APP_PASSWORD'),
    'USER_ROLE' : os.environ.get('USER_ROLE')
}

with app.app_context():
    db.create_all()

    admin_role = Role.query.filter_by(name=app_info['USER_ROLE']).first()
    if not admin_role:
        # if the admin role doesn't exist, create it
        admin_role = Role(name=app_info['USER_ROLE'])
        db.session.add(admin_role)
        db.session.commit()

    user = User.query.filter_by(username=app_info['APP_USER']).first()
    if not user:
        hashed_password = generate_password_hash(app_info['APP_PASSWORD']).decode('utf-8')
        admin_user = User(username=app_info['APP_USER'], password=hashed_password, active=True)
        db.session.add(admin_user)
        admin_user.roles.append(admin_role)
        db.session.commit()

# with app.app_context():
#     db.create_all()
#     user = User.query.filter_by(username=app_info['APP_USER']).first()
#     if user:
#         pass
#     else:
#         hashed_password = generate_password_hash(app_info['APP_PASSWORD']).decode('utf-8')
#         user = User(id=1, username='user', password=hashed_password, role='admin')
#         db.session.add(user)
#         db.session.commit()