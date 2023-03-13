import os
import ssl
from datetime import timedelta
from flask import Flask
from flask_security import Security
from flask_talisman import Talisman
from models import db, login_manager, user_datastore
from views import pb, bcrypt
from forms import csrf
from flask_migrate import Migrate

app = Flask(__name__)

# Configure content security policy
csp = {
    'default-src': ['\'self\'',
                    'stackpath.bootstrapcdn.com', 
                    'ajax.googleapis.com',
                    'cdn.jsdelivr.net'],
    'style-src': ['\'self\'',
                    'https://cdn.jsdelivr.net/npm/select2@4.0.13/dist/css/select2.min.css',
                    'https://stackpath.bootstrapcdn.com/bootstrap/4.4.1/css/bootstrap.min.css'],
    'img-src' : ['\'self\'', "data"],
    'script-src': ['\'self\'',
                    'https://ajax.googleapis.com/ajax/libs/jquery/3.4.1/jquery.min.js',
                    'https://cdn.jsdelivr.net/npm/select2@4.0.13/dist/js/select2.min.js',
                    'https://cdn.jsdelivr.net/npm/chart.js@2.8.0'],
    'font-src': ["'self'"],
    'connect-src': ["'self'"],
    'frame-src': ["'none'"],
    'object-src': ["'none'"]
}
Talisman(app, content_security_policy=csp, content_security_policy_nonce_in=['script-src'])

current_dir = os.path.dirname(os.path.abspath(__file__))

conn_info = {
    'POSTGRES_USER' : os.environ.get('POSTGRES_USER'),
    'POSTGRES_PASSWORD': os.environ.get('POSTGRES_PASSWORD'),
    'POSTGRES_URL' : os.environ.get('POSTGRES_URL')
}
POSTGRES_DB = os.environ.get('POSTGRES_DB')

ENV = os.environ.get('ENV')
if ENV == 'dev':
    conn_info['POSTGRES_URL'] = 'localhost'
else:
    conn_info['POSTGRES_URL'] = 'postgres'

app.register_blueprint(pb)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://{}:{}@{}:5432'.format(
    conn_info['POSTGRES_USER'], conn_info['POSTGRES_PASSWORD'], conn_info['POSTGRES_URL'])
app.config['SQLALCHEMY_BINDS'] = {
    f'{POSTGRES_DB}':"postgresql+psycopg2://{}:{}@{}:5432/playbook".format(
    conn_info['POSTGRES_USER'], conn_info['POSTGRES_PASSWORD'],conn_info['POSTGRES_URL']),
    "users":"postgresql+psycopg2://{}:{}@{}:5432/users".format(
    conn_info['POSTGRES_USER'], conn_info['POSTGRES_PASSWORD'], conn_info['POSTGRES_URL'])
    }
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=12)
app.config['SESSION_REFRESH_EACH_REQUEST'] = True
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get('SECURITY_PASSWORD_SALT')

db.init_app(app)
security = Security(app, user_datastore)
migrate = Migrate(app, db)
login_manager.init_app(app)
login_manager.login_view = 'pb.login'
bcrypt.init_app(app)
csrf.init_app(app)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8000, debug=True)
