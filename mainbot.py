
import slack_utility
import time
import canarytools
import requests
import vta
import re

VT_API_KEY = "-YOUR VT API KEY HERE-"
console = canarytools.Console(api_key='-YPUR CANARY API KEY HERE', domain='-YOUR CANARY DOMAIN HERE-')



def handle_command(slack_api, command, channel):
	"""
	Recieves commands directed for the bot, if they are valid perform action 
	else resends clarification
	"""
	EXAMPLE_COMMAND = 'do'
	if command.lower().startswith(EXAMPLE_COMMAND) or command.lower().startswith('incident'):
		slack_api.rtm_send_message(channel, 'Hey, I\'m your CSIRT bot, how\"\ may I help you?')
		for incident in console.incidents.all():
			canary_incident_type = incident.description
			canary_incident_IP = incident.src_host
			canary_incident_nodis = incident.node_id
			slack_api.rtm_send_message(channel,'%s -- %s -- %s' %(canary_incident_type,canary_incident_IP,canary_incident_nodis))
	elif ("https" in command.lower() or ("http" in command.lower() or ("www" in command.lower()))):
		command = (re.sub("<|>","",command.lower()))
		print command
		headers = {
  		"Accept-Encoding": "gzip, deflate",
  		"User-Agent" : "gzip,  My Python requests library example client or username"
  		}
		params = {'apikey': VT_API_KEY, 'resource':command}
		response = requests.post('https://www.virustotal.com/vtapi/v2/url/report'
		  ,params=params, headers=headers)
		json_response = response.text
		match = re.search(r'"positives": \w+',json_response)
		print command +"--"+match.group()
		vt_result = command +"--"+match.group()
		slack_api.rtm_send_message(channel,vt_result)
	elif command.lower().startswith('hello') or command.lower().startswith('hi') or command.lower().startswith('hey') or command.lower().startswith('hello') or command.lower().startswith('who are you'):
		slack_api.rtm_send_message(channel, 'Hey, I\'m your CSIRT bot, how may I help you?\n use incident CMD to query canary incident.\n use URL start with http or https or www to query URL reputation from VT. ')
	else:
		print 'Invalid Command: Not Understood'
		slack_api.rtm_send_message(channel, 'Invalid Command: Not Understood')
	
def main():
	"""
	Initiate the bot and call appropriate handler functions
	"""
	READ_WEBSOCKET_DELAY = 1 # 1 second delay between reading from firehose
	slack_api = slack_utility.connect()
	if slack_api.rtm_connect():
		print 'SLACK_BOT connected and running'
		while True:
			command, channel = slack_utility.parse_slack_response(slack_api.rtm_read())
			if command and channel:
				handle_command(slack_api, command, channel)
			time.sleep(READ_WEBSOCKET_DELAY)
	else:
		print 'Connection failed. Invalid Slack token or bot ID?' 

if __name__ == '__main__':
	main()
