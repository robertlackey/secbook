import re
import logging
from datetime import datetime
from urllib.parse import urlparse, urljoin
from flask import has_request_context, Blueprint, render_template, request, redirect, flash
from flask_bcrypt import Bcrypt
from flask_login import login_user, logout_user, current_user, login_required
from flask_security import roles_required
import pandas as pd
from forms import AddPlay, LoginForm, ArchivePlay, UnArchivePlay
from models import db, Playbook, User
from datetime import datetime
from extract_mitre import ExtractMitre
from mitre_map import MitreMap

class ContextFilter(logging.Filter):
    def filter(self, record):
        if current_user.is_authenticated:
            record.current_user = current_user.username
        else:
            record.current_user = ""
        if has_request_context():
            record.url = request.url
            record.remote_addr = request.remote_addr
        else:
            record.url = None
            record.remote_addr = None
        return True

"""
logging.basicConfig(
    filename="logs/app.log",
    format='datetime: %(asctime)s, level: %(levelname)s, src_ip: %(remote_addr)s, user: %(current_user)s, message: %(message)s, url: %(url)s',
    datefmt="%d/%b/%Y:%H:%M:%S %z",
    level=logging.INFO)
"""
f = ContextFilter()
logger = logging.getLogger("app.log")
logger.addFilter(f)

mitre_info = ExtractMitre()
mitre_map = MitreMap()
bcrypt = Bcrypt()

pb = Blueprint('pb', __name__)

@pb.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect("/")

    form = LoginForm()
    if form.validate_on_submit():
        print("validated")
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            logger.info("{} logged-in".format(user.username))
            login_user(user)
            next_page = request.args.get('next')
            if not next_page:
                return redirect("/")
            # validate the next_page URL
            # only allow relative URLs within the website
            if urlparse(next_page).netloc == '':
                next_page = urljoin(request.host_url, next_page)
                return redirect(next_page)
        else:
            logger.info("{} local login unsuccessful".format(user.username))
            flash('Login Unsuccessful. Please check username and password')

    return render_template('login.html', form=form)

@pb.route('/logout_local', methods=['GET'])
@login_required
def logout_local():
    logout_user()
    return redirect("/")

@pb.route('/', methods=['GET'])
@login_required
def index():
    plays = Playbook.query.filter_by(deleted=0).order_by(Playbook.play_name).all()
    #used for technology buttons

    play_buttons = []
    status = []
    for play in plays:
        status.append(play.playbook_status)
        play_buttons.append(play.mitre_tactic)
    play_buttons = list(dict.fromkeys(play_buttons))

    status = sorted(set(status))
    
    play_buttons_dict = {i:play_buttons.count(i) for i in play_buttons}

    labels = play_buttons_dict.keys()
    values = play_buttons_dict.values()

    play_count = Playbook.query.filter_by(deleted=0).count()
    archive_count = Playbook.query.filter_by(deleted=1).count()

    return render_template(
        'index.html', plays=plays,
        archive_count=archive_count, play_count=play_count,
        play_buttons=play_buttons, status=status, values=values, labels=labels
        )


@pb.route('/play/<int:id>', methods=['GET'])
@login_required
def play(id):
    """method to view plays"""
    archive = ArchivePlay()
    plays = Playbook.query.get_or_404(id)
    # versions = PlaybookVersion.query.filter_by(id=plays.id).all()

    def split_string_if_not_empty(value):
        if value and isinstance(value, str):
            return value.split(",")
        return value

    plays.mitre_id = split_string_if_not_empty(plays.mitre_id)
    plays.mitre_info_url = split_string_if_not_empty(plays.mitre_info_url)
    plays.mitre_info_subtechnique = split_string_if_not_empty(plays.mitre_info_subtechnique)
    plays.mitre_info_subtechnique_url = split_string_if_not_empty(plays.mitre_info_subtechnique_url)
    plays.mitre_info_platforms = split_string_if_not_empty(plays.mitre_info_platforms)
    if isinstance(plays.mitre_info_platforms, list):
        plays.mitre_info_platforms = sorted(set(plays.mitre_info_platforms))
        
    return render_template('play.html', plays=plays, archive=archive)

@pb.route('/add_play', methods=['GET', 'POST'])
@login_required
def add_play():
    tactics = mitre_map.get_tactics()
    combined_mitre_info = mitre_info.combine_mitre_info()

    form = AddPlay()

    if request.method == 'POST':
        #storing form fields in variable to add to database
        play_name = form.play_name.data
        playbook_owner = form.playbook_owner.data
        playbook_description = form.playbook_description.data
        mitre_tactic = request.form['mitre_tactic']
        mitre_id = request.form.getlist('mitre_id[]')
        severity = form.severity.data
        playbook_status = form.playbook_status.data
        deleted = 0

        def convert_to_list(mitre_method):
            try:
                initial_list = []
                for item in mitre_id:
                    id_list = re.findall(r"TA\d+|T\d+", item)
                    for i in id_list:
                        info = mitre_method(str(i))
                        if info is not None and info != '':
                            initial_list.append(info)
                return initial_list
            except:
                pass

        #try to get mitre info unless there is an error
        #github might be not working or the data might be changed to wrong format
        mitre_info_url = convert_to_list(mitre_info.get_url)
        mitre_info_tactic = convert_to_list(mitre_info.get_kill_chain_phase)
        mitre_os = convert_to_list(mitre_info.get_platforms)

        mitre_info_subtechnique = convert_to_list(mitre_info.get_subtechniques)
        mitre_info_subtechnique_url = convert_to_list(mitre_info.get_subtechniques_url)
        mitre_info_platforms = convert_to_list(mitre_info.get_platforms)
        
        mitre_id = ", ".join(mitre_id)
        try:
            mitre_info_url = ", ".join(mitre_info_url)
        except:
            pass
        if mitre_info_subtechnique == "":
            pass
        else:
            mitre_info_subtechnique = ", ".join(mitre_info_subtechnique)
        if mitre_info_subtechnique_url == "":
            pass
        else:
            mitre_info_subtechnique_url = ", ".join(mitre_info_subtechnique_url)
        mitre_info_platforms = ", ".join(mitre_info_platforms)

        #adding fields to database
        new_play = Playbook(
            user_id = current_user.username,
            play_name=play_name, 
            playbook_owner=playbook_owner,
            playbook_description=playbook_description,
            severity = severity,
            playbook_status = playbook_status,
            mitre_tactic=mitre_tactic,
            mitre_id=mitre_id,
            mitre_os=mitre_os,
            mitre_info_url=mitre_info_url,
            mitre_info_subtechnique=mitre_info_subtechnique,
            mitre_info_subtechnique_url=mitre_info_subtechnique_url,
            mitre_info_platforms=mitre_info_platforms,
            mitre_info_tactic=mitre_info_tactic,
            deleted=deleted
        )

        db.session.add(new_play)
        db.session.commit()

        return redirect('add_play')
    else:
        return render_template(
            "add_play.html", form=form, tactics=tactics,
            combined_mitre_info=combined_mitre_info)
    
#function to update a play if needed. All user input fields can be updated as necessary.
@pb.route('/update/<int:id>', methods=['POST', 'GET'])
@login_required
@roles_required('admin')
def update_play(id):
    """method to update plays"""
    form = AddPlay()
    tactics = mitre_map.get_tactics()
    combined_mitre_info = mitre_info.combine_mitre_info()

    plays = Playbook.query.get_or_404(id)

    form.playbook_owner.default = plays.playbook_owner
    form.playbook_status.default = plays.playbook_status
    form.severity.default = plays.severity
    form.playbook_description.default = plays.playbook_description

    form.process()

    if request.method == 'POST':
        plays.update_user = current_user.username
        plays.playbook_owner = request.form['playbook_owner']
        plays.date_updated = datetime.utcnow()
        plays.playbook_description = request.form['playbook_description']
        plays.mitre_tactic = request.form['mitre_tactic']
        plays.mitre_id = request.form.getlist('mitre_id[]')
        plays.playbook_status = request.form['playbook_status']
        plays.severity = request.form['severity']

        def convert_to_list(mitre_method):
            try:
                initial_list = []
                for item in plays.mitre_id:
                    id_list = re.findall(r"TA\d+|T\d+", item)
                    for i in id_list:
                        info = mitre_method(str(i))
                        if info is not None and info != '':
                            initial_list.append(info)
                return initial_list
            except:
                pass

        mitre_info_url = convert_to_list(mitre_info.get_url)
        mitre_info_subtechnique = convert_to_list(mitre_info.get_subtechniques)
        mitre_info_subtechnique_url = convert_to_list(mitre_info.get_subtechniques_url)
        mitre_info_platforms = convert_to_list(mitre_info.get_platforms)

        plays.mitre_id = ", ".join(plays.mitre_id)
        try:
            mitre_info_url = ", ".join(mitre_info_url)
        except:
            pass
        if mitre_info_subtechnique == "":
            pass
        else:
            mitre_info_subtechnique = ", ".join(mitre_info_subtechnique)
        if mitre_info_subtechnique_url == "":
            pass
        else:
            mitre_info_subtechnique_url = ", ".join(mitre_info_subtechnique_url)
        mitre_info_platforms = ", ".join(mitre_info_platforms)

        db.session.commit()
        return redirect('../play/'+str(id))

    else:
        return render_template(
            'update.html', plays=plays, form=form,
            tactics=tactics, combined_mitre_info=combined_mitre_info
            )

@pb.route('/status/<status>', methods=['GET', 'POST'])
@login_required
def status(status):
    """method update the status of plays"""
    plays = Playbook.query.filter_by(playbook_status=status).all()

    form = AddPlay()
    for play in plays:
        form.playbook_status.default = play.playbook_status
        form.process()

    if str(current_user.role) == 'read_write' or str(current_user.role) == 'admin':
        if request.method == 'POST':
            updated_status = Playbook.query.filter_by(id=play.id).update(dict(playbook_status=request.form['playbook_status']))
            db.session.commit()
            if Playbook.query.count().filter_by(playbook_status=status).all() > 0:
                return redirect('../status/'+str(status))
            else:
                return redirect('/')
    else:
        return "Not Authorized"

    return render_template('status.html', plays=plays, form=form)

@pb.route('/map.html', methods=['GET', 'POST'])
@login_required
def map():
    """method to map plays to mitre_map"""
    tactics = mitre_map.get_tactics()
    #creating pandas dataframe
    data_frame = pd.DataFrame.from_dict(tactics, orient='index').T
    data_frame.replace(to_replace=[None], value=" ", inplace=True)

    #function to find Mitre IDs in database and highlight cells with IDs present
    def custom_styles(val):
        plays = Playbook.query.filter_by(deleted=0).all()
        for play in plays:
            if play.mitre_id is not None:
                mitre_id = play.mitre_id.split(",")
                # price column styles
                for mitre_id1 in mitre_id:
                    #extracting mitre IDs from playbook string
                    try:
                        id_list = re.findall(r"(TA\d+|T\d+)[^\d+\.\d+]", mitre_id1)
                        id_sub_list = re.findall(r"\d+\.\d+", mitre_id1)
                        val_id = re.findall(r"(TA\d+|T\d+)[^\d+\.\d+]", val)
                        val_sub_id = re.findall(r"\d+\.\d+", val)
                        #iterating through the list of IDs in id_list
                        for item in id_list:
                                #if an ID is found, turn the background blue
                            if item == val_id[0]:
                                return "background-color: #3498DB"
                        for item in id_sub_list:
                            if item == val_sub_id[0]:
                                return "background-color: #3498DB"
                    except:
                        pass
        #if there is no ID in database, turn background white
        return "background-color: white"
    #defining table format
    data_frame = data_frame.style.set_properties(
        **{
            'white-space': 'pre-wrap',
            'font-size': '11pt',
            'background-color': '#edeeef',
            'border-color': 'black',
            'border-style' :'solid',
            'border-width': '1px',
            'border-collapse':'collapse'}).applymap(custom_styles).render()

    return render_template('map.html', tables=[data_frame])

#delete play by ID. Delete button added to play page
@pb.route('/deleted/<int:id>', methods=['GET', 'POST'])
@login_required
@roles_required('admin')
def deleted(id):
    """method to delete plays"""
    user = current_user
    print(user.roles)
    plays = Playbook.query.get_or_404(id)
    if request.method == 'POST' and "/play/"+str(id) in request.headers['Referer']:
        #updating database when page is submitted to the deleted/<id> page
        Playbook.query.filter_by(id=plays.id).update(dict(deleted=1))
        plays.date_updated = datetime.utcnow()
        db.session.commit()
        return redirect('/')
    else:
        return "Page Not Found"
    
#page to list archived plays
@pb.route('/archive.html', methods=['GET', 'POST'])
@login_required
def archive():
    plays = Playbook.query.filter_by(deleted=1).all()
    form = UnArchivePlay()
    return render_template('archive.html', plays=plays, form=form)

#method to unarchive plays
@pb.route('/unarchive/<int:id>', methods=['GET', 'POST'])
@login_required
@roles_required('admin')
def unarchive(id):
    print(current_user.roles)
    """defines a method to update plays with archive=1"""
    plays = Playbook.query.get_or_404(id)
    if request.method == 'POST' and "archive.html" in request.headers['Referer']:
        Playbook.query.filter_by(id=plays.id).update(dict(deleted=0))
        plays.date_updated = datetime.utcnow()
        db.session.commit()
        return redirect('/')
    else:
        return "Page Not Found"


# @pb.route('/update_account/<int:id>', methods=['GET', 'POST'])
# @login_required
# def update_account(id):
#     if str(current_user.role) == 'admin' or current_user.id == id:
#         form = UpdateAccount()
#         users = LocalUser.query.get_or_404(id)

#         if request.method == "POST":
#             if request.form['password'] != "" and request.form['confirm_password'] != "":
#                 hashed_password = bcrypt.generate_password_hash(request.form['password']).decode("utf-8")
#                 users.password = hashed_password
#             db.session.commit()
#             return redirect("/accounts")

#         return render_template("update_account.html", users=users, form=form)
#     else:
#         return "Not Authorized"
@pb.route('/count')
@login_required
def count():
    plays = Playbook.query.filter_by(deleted=0).all()
    user_list = []
    for play in plays:
        user_list.append(play.user_id)
    user_dict = {i:user_list.count(i) for i in user_list}
    labels = user_dict.keys()
    values = user_dict.values()
    return render_template("count.html", values=values, labels=labels)
