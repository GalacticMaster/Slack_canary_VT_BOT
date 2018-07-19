# Slack_canary_VT_BOT

BOT that query canary incident and URL reputation to VT

Installation


pip install slackclient
mainbot.py : main code of the slackbot
slack_utility.py : contains utility functions for the slackbot
set environment variable with your token and bot's name
$ export SLACK_TOKEN=<your_token_here>
$ export BOTNAME=<your_botname_here>

Start the slackbot
python mainbot.py

