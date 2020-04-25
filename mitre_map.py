import requests
import json
import pandas as pd
import itertools
from itertools import zip_longest

class mitre_map:
	def __init__(self):
		#defining get request to pull data from github
		r = requests.get("https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json")
		try:
			self.json_data = r.json()
		except:
			pass

	def get_tactics(self):
		self.tactics = []
		for self.value in self.json_data['objects']:
			try:
				if "TA" in self.value['external_references'][0]['external_id']:
					self.tactics.append(self.value['name'])
			except:
				pass
		return self.tactics

	def collection(self):
		collection = []	
		for self.value in self.json_data['objects']:
			try:
				phase = self.value['kill_chain_phases'][0]['phase_name'].lower()
				try:
					phase = phase.replace("-", " ")
				except:
					pass
				if phase == self.tactics[0].lower():
					collection.append(self.value['name'] + " " + self.value['external_references'][0]['external_id'])
			except:
				pass
		return collection

	def command_and_control(self):
		command_and_control = []
		for self.value in self.json_data['objects']:
			try:
				phase = self.value['kill_chain_phases'][0]['phase_name'].lower()
				try:
					phase = phase.replace("-", " ")
				except:
					pass
				if phase == self.tactics[1].lower():
					command_and_control.append(self.value['name'] + " " + self.value['external_references'][0]['external_id'])
			except:
				pass
		return command_and_control

	def credential_access(self):
		credential_access = []
		for self.value in self.json_data['objects']:
			try:
				phase = self.value['kill_chain_phases'][0]['phase_name'].lower()
				try:
					phase = phase.replace("-", " ")
				except:
					pass
				if phase == self.tactics[2].lower():
					credential_access.append(self.value['name'] + " " + self.value['external_references'][0]['external_id'])
			except:
				pass
		return credential_access

	def defense_evasion(self):
		defense_evasion = []
		for self.value in self.json_data['objects']:
			try:
				phase = self.value['kill_chain_phases'][0]['phase_name'].lower()
				try:
					phase = phase.replace("-", " ")
				except:
					pass
				if phase == self.tactics[3].lower():
					defense_evasion.append(self.value['name'] + " " + self.value['external_references'][0]['external_id'])
			except:
				pass
		return defense_evasion

	def discovery(self):
		discovery = []
		for self.value in self.json_data['objects']:
			try:
				phase = self.value['kill_chain_phases'][0]['phase_name'].lower()
				try:
					phase = phase.replace("-", " ")
				except:
					pass
				if phase == self.tactics[4].lower():
					discovery.append(self.value['name'] + " " + self.value['external_references'][0]['external_id'])
			except:
				pass
		return discovery

	def execution(self):
		execution = []
		for self.value in self.json_data['objects']:
			try:
				phase = self.value['kill_chain_phases'][0]['phase_name'].lower()
				try:
					phase = phase.replace("-", " ")
				except:
					pass
				if phase == self.tactics[5].lower():
					execution.append(self.value['name'] + " " + self.value['external_references'][0]['external_id'])
			except:
				pass
		return execution

	def exfiltration(self):
		exfiltration = []
		for self.value in self.json_data['objects']:
			try:
				phase = self.value['kill_chain_phases'][0]['phase_name'].lower()
				try:
					phase = phase.replace("-", " ")
				except:
					pass
				if phase == self.tactics[6].lower():
					exfiltration.append(self.value['name'] + " " + self.value['external_references'][0]['external_id'])
			except:
				pass
		return exfiltration

	def impact(self):
		impact = []
		for self.value in self.json_data['objects']:
			try:
				phase = self.value['kill_chain_phases'][0]['phase_name'].lower()
				try:
					phase = phase.replace("-", " ")
				except:
					pass
				if phase == self.tactics[7].lower():
					impact.append(self.value['name'] + " " + self.value['external_references'][0]['external_id'])
			except:
				pass
		return impact

	def initial_access(self):
		initial_access = []
		for self.value in self.json_data['objects']:
			try:
				phase = self.value['kill_chain_phases'][0]['phase_name'].lower()
				try:
					phase = phase.replace("-", " ")
				except:
					pass
				if phase == self.tactics[8].lower():
					initial_access.append(self.value['name'] + " " + self.value['external_references'][0]['external_id'])

			except:
				pass
		return initial_access

	def lateral_movement(self):
		lateral_movement = []
		for self.value in self.json_data['objects']:
			try:
				phase = self.value['kill_chain_phases'][0]['phase_name'].lower()
				try:
					phase = phase.replace("-", " ")
				except:
					pass
				if phase == self.tactics[9].lower():
					lateral_movement.append(self.value['name'] + " " + self.value['external_references'][0]['external_id'])
			except:
				pass
		return lateral_movement

	def persistence(self):
		persistence = []
		for self.value in self.json_data['objects']:
			try:
				phase = self.value['kill_chain_phases'][0]['phase_name'].lower()
				try:
					phase = phase.replace("-", " ")
				except:
					pass
				if phase == self.tactics[10].lower():
					persistence.append(self.value['name'] + " " + self.value['external_references'][0]['external_id'])
			except:
				pass
		return persistence

	def priv_esc(self):
		priv_esc = []
		for self.value in self.json_data['objects']:
			try:
				phase = self.value['kill_chain_phases'][0]['phase_name'].lower()
				try:
					phase = phase.replace("-", " ")
				except:
					pass
				if phase == self.tactics[11].lower():
					priv_esc.append(self.value['name'] + " " + self.value['external_references'][0]['external_id'])
			except:
				pass
		return priv_esc

def main():
	t = mitre_map()
	t.get_tactics()
	for i in t.collection():
		print(i)

if __name__ == '__main__':
	main()

