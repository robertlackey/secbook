from flask import render_template, request, redirect
from .models import Playbook
from . import db

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
