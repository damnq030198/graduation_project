import flask
from flask import request, jsonify
from flask_cors import CORS
import json
from mitre import MitreParser
import os
import yaml
from datetime import datetime
import time
import config
from pathlib import Path

app = flask.Flask(__name__)
CORS(app)

rules = []
parsers = []

message = ''

def get_all_rules(folder):
    files = []
    for r, d, f in os.walk(folder):
        for file in f:
            print('tenfile: ', file)
            if file.endswith('.yml'):
                files.append(os.path.join(r, file))
    return files

def parse_message(message):
    get_field = message.split("\n")
    logs_dict = {}
    try:
        for element in get_field:
            elements = element.split(':' , 1)
            if elements[1] == '' or elements[1] == ' ':
                elements[1] = 'None'  
            logs_dict[elements[0]] = elements[1]
    except Exception as ex:
        print(ex, ':', message)
    return logs_dict

@app.route('/get_message_logstash', methods=['POST'])
def get_message_logstash():
    log = request.get_json(force=True)
    log_m = log['message']
    log_message = parse_message(log_m)
    try:
        for parser in parsers:
            if parser.check(log_message):
                info = parser.info()
                send_notification_alert(info)
                return jsonify({
                    'mitre-detected': "1",
                    'info': info
                })
                break
        return jsonify({
            'mitre-detected': "0"
        })
    except Exception as ex:
        print(ex)
        return jsonify({
            'mitre-detected': "Warning: parse errors"
        })


@app.route('/send_notification_alert', methods=['GET'])
def send_notification_alert(info):
    return jsonify({
        'status': 'Warning dangerous process detected by mitre rule',
        'info': info
    })


try:
    print('start')
    rules = get_all_rules(Path(config.RULE_PATH))
    parsers = [MitreParser(rule) for rule in rules]
    print('done')
except Exception as ex:
    print('error at main:', ex)

if __name__ == "__main__":
    app.run(host='localhost', port=6969) 