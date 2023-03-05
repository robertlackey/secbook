import requests
import json

class extract_mitre:
    def __init__(self):
        # defining get request to pull data from github
        r = requests.get("https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json")
        try:
            self.json_data = r.json()
        except:
            pass

    def get_attribute(self, mitre_id, attribute):
        # getting the specified attribute based on the mitre_id entered in playbook form
        for json_object in self.json_data['objects']:
            try:
                if json_object['external_references'][0]['external_id'] == mitre_id:
                    if attribute == 'id':
                        return json_object['external_references'][0]['external_id']
                    elif attribute == 'name':
                        return json_object['name']
                    elif attribute == 'description':
                        return json_object['description']
                    elif attribute == 'url':
                        return json_object['external_references'][0]['url']
                    elif attribute == 'platforms':
                        return ', '.join(json_object['x_mitre_platforms'])
                    elif attribute == 'kill_chain_phase':
                        return json_object['kill_chain_phases'][0]['phase_name']
            except:
                pass
