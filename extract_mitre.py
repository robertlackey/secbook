
import requests
import json
import os

class ExtractMitre:
    VALID_ATTRIBUTES = {'id', 'name', 'description', 'url', 'platforms', 'kill_chain_phase'}

    def __init__(self):
        self.json_data = self.fetch_mitre_data()

    def fetch_mitre_data(self):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        attack_file = current_dir + "/enterprise-attack.json"
        if os.path.isfile(attack_file):
            with open(attack_file) as f:
                return json.load(f)
        else:
            r = requests.get("https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json")
            try:
                r.raise_for_status()
                return r.json()
            except requests.exceptions.RequestException as e:
                raise Exception("Failed to fetch MITRE data: " + str(e))

    def get_id(self, mitre_id):
        """getting the mitre mitre_id based on the mitre_id entered in playbook form"""
        for value in self.json_data['objects']:
            try:
                if value['external_references'][0]['external_id'] == mitre_id:
                    mitre_id = value['external_references'][0]['external_id']
                    return mitre_id
            except:
                pass

    def get_name(self, mitre_id):
        """getting the mitre name based on the mitre_id entered in playbook form"""
        for value in self.json_data['objects']:
            try:
                if value['external_references'][0]['external_id'] == mitre_id:
                    name = value['name']
                    return name
            except:
                pass

    def get_description(self, mitre_id):
        """getting the description based on the mitre_id entered in playbook form"""
        for value in self.json_data['objects']:
            try:
                if value['external_references'][0]['external_id'] == mitre_id:
                    description = value['description']
                    return description
            except:
                pass

    def get_url(self, mitre_id):
        """getting the mitre url based on the mitre_id entered in playbook form"""
        for value in self.json_data['objects']:
            try:
                if value['external_references'][0]['external_id'] == mitre_id:
                    url = value['external_references'][0]['url']
                    return url
            except:
                pass

    def get_platforms(self, mitre_id):
        """getting the mitre OS/platform info based on the mitre_id entered in playbook form"""
        for value in self.json_data['objects']:
            try:
                if value['external_references'][0]['external_id'] == mitre_id:
                    platforms = ', '.join(value['x_mitre_platforms'])
                    return platforms
            except:
                pass

    def get_kill_chain_phase(self, mitre_id):
        """return list of operating systems for each technique"""
        for value in self.json_data['objects']:
            try:
                if value['external_references'][0]['external_id'] == mitre_id:
                    platforms = value['kill_chain_phases'][0]['phase_name']
                    return platforms
            except:
                pass

    def get_subtechniques(self, mitre_id):
        """return mitre subtechniques as comma separated string"""
        subtechniques = []
        #getting the mitre mitre_id based on the mitre_id entered in playbook form
        for item in self.json_data['objects']:
            try:
                if mitre_id in item['external_references'][0]['external_id']:
                    if item['x_mitre_is_subtechnique'] == True:
                        name = item['name']
                        external_id = item['external_references'][0]['external_id']
                        subtechniques.append(external_id + " " + name)
            except:
                pass
        return ", ".join(subtechniques)

    def get_subtechniques_url(self, mitre_id):
        """returns mitre subtechnique urls as comma separated string"""
        subtechniques_url = []
        for item in self.json_data['objects']:
            try:
                if mitre_id in item['external_references'][0]['external_id']:
                    if item['x_mitre_is_subtechnique'] == True:
                        url = item['external_references'][0]['url']
                        subtechniques_url.append(url)
            except:
                pass
        return ", ".join(subtechniques_url)

    def combine_mitre_info(self):
        """gets mitre info combined"""
        mitre_info = {}
        for value in self.json_data['objects']:
            try:
                if "T" in value['external_references'][0]['external_id']:
                    mitre_id = value['external_references'][0]['external_id']
                    mitre_info[mitre_id] = value['name']
            except:
                pass
        return mitre_info

if __name__ == "__main__":
    extractor = ExtractMitre()
    print(extractor.get_attribute('T1081', 'url'))
    # print(extractor.get_subtechniques('T1174'))
    # print(extractor.get_subtechniques_url('T1003'))
