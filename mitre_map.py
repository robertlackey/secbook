import os
import json
import requests
from collections import defaultdict


class MitreMap:
    """
    A class to retrieve tactics and associated techniques from the MITRE ATT&CK framework.

    Example Usage:
    >>> mm = MitreMap()
    >>> tactics = mm.get_tactics()
    """

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

    def get_tactics(self):
        """
        Retrieves tactics and associated techniques from the JSON data.

        Returns:
            A defaultdict with tactics as keys and techniques as values.
        """
        tactics = defaultdict(list)

        # Retrieve the names of all tactics
        for obj in self.json_data["objects"]:
            if obj.get("type") == "x-mitre-tactic":
                name = obj["name"]
                tactics[name] = []

        # Retrieve the techniques associated with each tactic
        for obj in self.json_data["objects"]:
            if obj.get("type") == "attack-pattern":
                for phase in obj["kill_chain_phases"]:
                    for tactic in tactics:
                        if tactic.lower() in phase["phase_name"].replace("-", " ").lower():
                            techniques = f"{obj['external_references'][0]['external_id']}\n{obj['name']}"
                            tactics[tactic].append(techniques)

        # Sort the techniques for each tactic alphabetically
        sorted_tactics = {tactic: sorted(techniques) for tactic, techniques in tactics.items()}

        return sorted_tactics
