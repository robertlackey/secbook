import requests
from collections import defaultdict


class MitreMap:
    def __init__(self):
        # Define get request to pull data from github
        r = requests.get("https://raw.githubusercontent.com/mitre/cti/subtechniques/enterprise-attack/enterprise-attack.json")
        try:
            self.json_data = r.json()
        except:
            print("Failed to retrieve JSON data")

    def get_tactics(self):
        # Create a dictionary to store tactics and their associated techniques
        self.tactics = defaultdict(list)
        sorted_tactics = defaultdict(list)

        def get_phases():
            # Retrieve the names of all tactics
            for mitre_object in self.json_data['objects']:
                try:
                    if "TA" in mitre_object['external_references'][0]['external_id']:
                        name = mitre_object['name']
                        self.tactics[name] = []
                except:
                    pass
        get_phases()

        # Retrieve the techniques associated with each tactic
        for mitre_object in self.json_data['objects']:
            try:
                phase = mitre_object['kill_chain_phases']
                for tactic in self.tactics:
                    for i in phase:
                        p = i['phase_name'].replace("-", " ")
                        if tactic.lower() in p:
                            self.tactics[tactic].append(mitre_object['external_references'][0]['external_id'] + "\n" + mitre_object['name'])
            except:
                pass

        # Sort the techniques for each tactic alphabetically
        for k,v in self.tactics.items():
            sorted_tactics[k] = sorted(v)

        return sorted_tactics

if __name__ == '__main__':
    mitre_map = MitreMap()
    tactics = mitre_map.get_tactics()
    print(tactics)
