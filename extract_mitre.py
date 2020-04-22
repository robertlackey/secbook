import requests
import json

class extract_mitre:
	def __init__(self):
		#defining get request to pull data from github
		r = requests.get("https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json")
		try:
			self.json_data = r.json()
		except:
			pass

	def get_id(self, id):
		#getting the mitre id based on the mitre_id entered in playbook form
		for value in self.json_data['objects']:
			try:
				if value['external_references'][0]['external_id']==id:
					mitre_id = value['external_references'][0]['external_id']
					return mitre_id
			except:
				pass

	def get_name(self, id):
		#getting the mitre name based on the mitre_id entered in playbook form
		for value in self.json_data['objects']:
			try:
				if value['external_references'][0]['external_id']==id:
					name = value['name']
					return name
			except:
				pass

	def get_description(self, id):
		#getting the description based on the mitre_id entered in playbook form
		for value in self.json_data['objects']:
			try:
				if value['external_references'][0]['external_id']==id:
					description = value['description']
					return description
			except:
				pass

	def get_url(self, id):
		#getting the mitre url based on the mitre_id entered in playbook form
		for value in self.json_data['objects']:
			try:
				if value['external_references'][0]['external_id']==id:
					url = value['external_references'][0]['url']
					return url
			except:
				pass

	def get_platforms(self, id):
		#getting the mitre OS/platform info based on the mitre_id entered in playbook form
		for value in self.json_data['objects']:
			try:
				if value['external_references'][0]['external_id']==id:
					platforms = ', '.join(value['x_mitre_platforms'])
					return platforms
			except:
				pass
				
	def get_kill_chain_phase(self, id):
		for value in self.json_data['objects']:
			try:
				if value['external_references'][0]['external_id']==id:
					platforms = value['kill_chain_phases'][0]['phase_name']
					return platforms
			except:
				pass
		