from flask import Flask, render_template, request, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from extract_mitre import *
from mitre_map import *
import pandas as pd
from itertools import zip_longest
import requests
import json

mitre_info = extract_mitre()
mitre_map = mitre_map()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

#database class to store playbook data
class playbook(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	play_name = db.Column(db.String(200), nullable=False)
	playbook_description = db.Column(db.String(500), default=" ")
	playbook_owner = db.Column(db.String(200), default="SGS")
	playbook_type = db.Column(db.String(500), default=" ")
	date_added = db.Column(db.DateTime, default=datetime.utcnow())
	date_updated = db.Column(db.DateTime)
	detection_technology = db.Column(db.String(500), default=" ")
	category = db.Column(db.String(500), default=" ")
	subcategory = db.Column(db.String(500), default=" ")
	mitre_tactic = db.Column(db.String(300), default=" ")
	mitre_id = db.Column(db.String(200), default=" ")
	mitre_os = db.Column(db.String(500), default=" ")
	splunk_query = db.Column(db.String, default=" ")
	run_frequency = db.Column(db.String(200), default=" ")
	analyst_action = db.Column(db.String(), default=" ")
	deleted = db.Column(db.Integer, default=0)

	#mitre data tables to be stored after pulled from mitre github
	mitre_info_description = db.Column(db.String(), default=" ")
	mitre_info_name = db.Column(db.String(), default=" ")
	mitre_info_url = db.Column(db.String(), default=" ")
	mitre_info_tactic = db.Column(db.String(), default=" ")

	def __repr__(self):
		return "<Play %r>" % self.id

@app.route('/', methods=['GET'])
def index():
	plays = playbook.query.filter_by(deleted=0).all()
	return render_template('index.html', plays=plays)

@app.route('/play/<int:id>', methods=['GET'])
def play(id):
	plays = playbook.query.get_or_404(id)
	return render_template('play.html', plays=plays)

@app.route('/add_play', methods=['GET', 'POST'])
def add_play():
    detection_technology = [
        "splunk1",
        "splunk2",
        "splunk3",
        "Micro... No"
    ]
    category = [
        "category1",
        "category2",
        "category3"
    ]
    playbook_type = [
        "type1",
        "type2",
        "type3"
    ]
    subcategory = [
        "subcategory1",
        "subcategory2",
        "subcategory3"
    ]
    if request.method == 'POST':
        #storing form fields in variable to add to database
        play_name = request.form['play_name']
        playbook_owner = request.form['playbook_owner']
        detection_technology_selected = request.form['detection_technology']
        playbook_description = request.form['playbook_description']
        playbook_type_selected = request.form['playbook_type']
        category_selected = request.form['category']
        subcategory_selected = request.form['subcategory']
        mitre_id = request.form['mitre_id']
        splunk_query = request.form['splunk_query']
        run_frequency = request.form['run_frequency']
        analyst_action = request.form['analyst_action']
        deleted = 0

        #try to get mitre info unless there is an error
        #github might be not working or the data might be changed to wrong format
        try:
            mitre_info_name = mitre_info.get_attribute(mitre_id, 'id')
        except:
            mitre_info_name = None
        try:
            mitre_info_description = mitre_info.get_attribute(mitre_id, 'description')
        except:
            mitre_info_description = None
        try:
            mitre_info_url = mitre_info.get_attribute(mitre_id, 'url')
        except:
            mitre_info_url = None
        try:
            mitre_info_tactic = mitre_info.get_attribute(mitre_id, 'kill_chain_phases')
        except:
            mitre_info_tactic = None
        try:
            mitre_os = mitre_info.get_attribute(mitre_id, 'platforms')
        except:
            mitre_os = None

        #adding fields to database
        new_play = Playbook(
            play_name=play_name, 
            playbook_owner=playbook_owner,
            detection_technology=detection_technology_selected,
            playbook_description=playbook_description,
            playbook_type=playbook_type_selected,
            category=category_selected,
            subcategory=subcategory_selected,
            mitre_id=mitre_id,
            mitre_os=mitre_os,
            splunk_query=splunk_query,
            run_frequency=run_frequency,
            analyst_action=analyst_action,
            mitre_info_name=mitre_info_name,
            mitre_info_description=mitre_info_description,
            mitre_info_url=mitre_info_url,
            mitre_info_tactic=mitre_info_tactic,
            deleted=deleted
        )

        db.session.add(new_play)
        db.session.commit()

        return redirect('/add_play')
    else:
        plays = Playbook.query.order_by(Playbook.date_added).all()
        return render_template("add_play.html", category=category, subcategory=subcategory, playbook_type=playbook_type, detection_technology=detection_technology)
    
#function to update a play if needed. All user input fields can be updated as necessary.
@app.route('/update/<int:id>', methods=['POST', 'GET'])
def update_play(id):
	detection_technology = [
			"splunk1",
			"splunk2",
			"splunk3",
			"Micro... No"
			]
	category = [
			"category1",
			"category2",
			"category3"
			]
	playbook_type = [
				"type1",
				"type2",
				"type3"
				]
	subcategory = [
				"subcategory1",
				"subcategory2",
				"subcategory3"
				]
	plays = playbook.query.get_or_404(id)

	if request.method == 'POST':
		plays.play_name = request.form['play_name']
		plays.playbook_owner = request.form['playbook_owner']
		plays.detection_technology = request.form['detection_technology']
		plays.date_updated = datetime.utcnow()
		plays.playbook_description = request.form['playbook_description']
		plays.playbook_type = request.form['playbook_type']
		plays.category = request.form['category']
		plays.subcategory = request.form['subcategory']
		plays.mitre_id = request.form['mitre_id']
		plays.splunk_query = request.form['splunk_query']
		plays.run_frequency = request.form['run_frequency']
		plays.analyst_action = request.form['analyst_action']

		try:
			db.session.commit()
			return redirect('../play/'+str(id))
		except:
			return "There was an issue with your request"

	else:
		return render_template('update.html', plays=plays, category=category, subcategory=subcategory, playbook_type=playbook_type, detection_technology=detection_technology)

@pb.route('/map.html', methods=['GET','POST'])
def map():
	tactics = mitre_map.get_tactics()
	#creating pandas dataframe
	df = pd.DataFrame.from_dict(tactics, orient='index').T
	df.replace(to_replace=[None], value=" ", inplace=True)

	#function to find Mitre IDs in database and highlight cells with IDs present
	def custom_styles(val):
		plays = Playbook.query.filter_by(deleted=0).all()
		for play in plays:
			mitre_id = play.mitre_id.split(",")
			# price column styles
			for mitre_id1 in mitre_id:
				#extracting mitre IDs from playbook string
				try:
					id_list = re.findall(r"(TA\d+|T\d+)[^\d+\.\d+]", mitre_id1)
					id_sub_list = re.findall(r"\d+\.\d+", mitre_id1)
					val_id = re.findall(r"(TA\d+|T\d+)[^\d+\.\d+]", val)
					val_sub_id =  re.findall(r"\d+\.\d+", val)
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
	df = df.style.set_properties(**{'white-space': 'pre-wrap','font-size': '11pt','background-color': '#edeeef','border-color': 'black','border-style' :'solid' ,'border-width': '1px','border-collapse':'collapse'}).applymap(custom_styles).render()

	return render_template('map.html', tables=[df])

#delete play by ID name. Delete button added to play page
@app.route('/deleted/<int:id>', methods=['GET','POST'])
def deleted(id):
	plays = playbook.query.get_or_404(id)
	if request.method == 'POST':
		updated_deleted = playbook.query.filter_by(id=plays.id).update(dict(deleted=1))
		db.session.commit()
		return redirect('/')

@app.route('/archive.html', methods=['GET','POST'])
def archive():
	plays = playbook.query.filter_by(deleted=1).all()
	return render_template('archive.html', plays=plays)

@app.route('/unarchive/<int:id>', methods=['GET','POST'])
def unarchive(id):
	plays = playbook.query.get_or_404(id)
	if request.method == 'POST':
		updated_deleted = playbook.query.filter_by(id=plays.id).update(dict(deleted=0))
		db.session.commit()
		return redirect('/')

if __name__ == '__main__':
	app.run(debug=True)
