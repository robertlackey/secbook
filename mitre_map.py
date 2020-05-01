import requests
from collections import defaultdict

class mitre_map:
	def __init__(self):
		#defining get request to pull data from github
		r = requests.get("https://raw.githubusercontent.com/mitre/cti/subtechniques/enterprise-attack/enterprise-attack.json")
		try:
			self.json_data = r.json()
		except:
			pass

	def get_tactics(self):
		self.tactics = defaultdict(list)
		sorted_tactics = defaultdict(list)

		def get_phases():
			for self.value in self.json_data['objects']:
				try:
					if "TA" in self.value['external_references'][0]['external_id']:
						name = self.value['name']
						self.tactics[name] = []
				except:
					pass
		get_phases()
		
		for self.value in self.json_data['objects']:
			try:

				phase = self.value['kill_chain_phases']
				for x in self.tactics:
					for i in phase:
						p = i['phase_name'].replace("-", " ")
						if x.lower() in p:
							self.tactics[x].append(self.value['external_references'][0]['external_id'] + "\n" + self.value['name'])
			except:
				pass
		for k,v in self.tactics.items():
			sorted_tactics[k] = sorted(v)

		return sorted_tactics
