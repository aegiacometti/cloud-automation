#!/usr/bin/env python3

# Script to send ACI faults and events to Slack or WebEx Teams.
# Python dependencies: slackclient (1.3.2) and acitoolkit (0.4)
#
# Configure the following variables for your setup:
#
# match_fault_severity
# plaform
# slack_channel
# slack_bot_oauth
# webex_teams_token
# webex_teams_room_id

import acitoolkit
from slackclient import SlackClient
import requests
import json

# Fault Severities descriptions

# critical:	A service-affecting condition that requires immediate corrective action. For example, this severity could
#           indicate that the managed object is out of service and its capability must be restored.
# major:    A service-affecting condition that requires urgent corrective action. For example, this severity could
#           indicate a severe degradation in the capability of the managed object and that its full capability must be
#           restored.
# minor:	A nonservice-affecting fault condition that requires corrective action to prevent a more serious fault from
#           occurring. For example, this severity could indicate that the detected alarm condition is not currently
#           degrading the capacity of the managed object.
# warning:	A potential or impending service-affecting fault that currently has no significant effects in the system.
#           An action should be taken to further diagnose, if necessary, and correct the problem to prevent it from
#           becoming a more serious service-affecting fault.
# info: 	A basic notification or informational message that is possibly independently insignificant.
#           (Used only for events)
# cleared:	A notification that the condition that caused the fault has been resolved, and the fault has been cleared.
match_fault_severity = ['critical', 'major', 'minor']

# Platform to send the messages
# slack
# webex_teams
platform = 'webex_teams'

# Slack configuration
slack_channel = 'net-dev'
slack_bot_oauth = 'xxxx'

# WebEx Teams configuration
# Get developer token at: https://developer.webex.com/docs/api/v1/messages/create-a-message
webex_teams_token = 'xxx'
webex_teams_room_id = 'xxx'

# Connection to ACI
URL = ''
LOGIN = ''
PASSWORD = ''

def send_msg_webex_teams(msg):
    msg = "```\n" + msg + "\n```"
    header = {"Authorization": "Bearer %s" % webex_teams_token,
              "Content-Type": "application/json"}
    data = {"roomId": webex_teams_room_id,
            "markdown": msg}
    res = requests.post("https://api.ciscospark.com/v1/messages/", headers=header, data=json.dumps(data), verify=True)

    if res.status_code == 200:
        print("your message was successfully posted to Webex Teams")
    else:
        print("failed with statusCode: %d" % res.status_code)
        if res.status_code == 404:
            print("please check the bot is in the room you're attempting to post to...")
        elif res.status_code == 400:
            print("please check the identifier of the room you're attempting to post to...")
        elif res.status_code == 401:
            print("please check if the access token is correct...")


def send_msg_slack(msg):
    slack_client = SlackClient(slack_bot_oauth)
    msg = "```" + msg + "```"
    slack_client.api_call("chat.postMessage", channel=slack_channel, text=msg)


def msg_dispatcher(msg):
    print(msg)
    if platform == 'slack':
        send_msg_slack(msg)
    elif platform == 'webex_teams':
        send_msg_webex_teams(msg)


def main():
    session = acitoolkit.Session(URL, LOGIN, PASSWORD)
    session.login()
    subscribe_to_events(session)


def subscribe_to_events(apic_session):
    acitoolkit.Tenant.subscribe(apic_session, only_new=True)
    acitoolkit.AppProfile.subscribe(apic_session, only_new=True)
    acitoolkit.EPG.subscribe(apic_session, only_new=True)
    acitoolkit.Faults.subscribe_faults(apic_session, only_new=True)
    msg_dispatcher("Listening for Events & Faults...")

    while True:
        if acitoolkit.Tenant.has_events(apic_session):
            event = acitoolkit.Tenant.get_event(apic_session)
            if event.is_deleted():
                status = "has been deleted"
            else:
                status = "has been created/modified"
            msg_dispatcher("Tenant Event: {} {}".format(event.dn, status))

        elif acitoolkit.AppProfile.has_events(apic_session):
            event = acitoolkit.AppProfile.get_event(apic_session)
            if event.is_deleted():
                status = "has been deleted"
            else:
                status = "has been created/modified"
            msg_dispatcher("AppProfile Event: {} {}".format(event.dn, status))

        elif acitoolkit.EPG.has_events(apic_session):
            event = acitoolkit.EPG.get_event(apic_session)
            if event.is_deleted():
                status = "has been deleted"
            else:
                status = "has been created/modified"
            msg_dispatcher("EPG Event: {} {}".format(event.dn, status))

        elif acitoolkit.Faults.has_faults(apic_session):
            fault = acitoolkit.Faults.get_faults(apic_session)
            if fault[0] is not None and fault[0].severity in match_fault_severity:
                message = [
                    'System Faults:',
                    '    Description         : ' + fault[0].descr,
                    '    Distinguished Name  : ' + fault[0].dn,
                    '    Rule                : ' + fault[0].rule,
                    '    Severity            : ' + fault[0].severity,
                    '    Type                : ' + fault[0].type,
                    '    Domain              : ' + fault[0].domain,
                    '    Subject             : ' + fault[0].subject,
                    '    Cause               : ' + fault[0].cause,
                ]
                msg_dispatcher("\n".join(message))


if __name__ == '__main__':
    main()