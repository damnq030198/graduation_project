from flask import  Flask, request, Response
from flask_cors import CORS
from flask import jsonify
import json
from datetime import datetime
import time
import dection
import ipdomain

app = Flask(__name__)
CORS(app)

@app.route('/api/get', methods=['POST'])
def getdata():
    input = request.get_json(force=True)
    computer_name = input['computer_name']
    time_start = int(datetime.strptime(input['from'], '%m/%d/%y %H:%M:%S').timestamp()) 
    time_end  = int(datetime.strptime(input['to'], '%m/%d/%y %H:%M:%S').timestamp())
    data = dection.query_search(time_start ,time_end, computer_name)
    return jsonify({
            "result": {
                "data": data}})

@app.route('/api/tree', methods=['POST'])
def buildtree():
    process = request.get_json(force=True)
    data = dection.dict_tree_process(process)
    # print(data)
    if data:
        if type(data) == type(list()):
            result = data[0]
        else:
            result = data
    else:
        result = "Not Found"
    return jsonify({
            "result": {
                "data": result}})

@app.route('/computer_list', methods=['GET'])
def computer_list(): 
    return Response(dection.realTime(),mimetype="text/event-stream")

@app.route('/detail', methods=['POST'])
def computer_info() :
    input = request.get_json(force=True)
    computer_name = input['computer_name']
    data = dection.detail(computer_name)
    return jsonify({
            "result": {
                "data": data}})

@app.route('/all', methods=['POST'])
def processcount():
    input = request.get_json(force=True)
    computer_name = input['computer_name']
    time_start = int(datetime.strptime(input['from'], '%m/%d/%y %H:%M:%S').timestamp())
    time_end  = int(datetime.strptime(input['to'], '%m/%d/%y %H:%M:%S').timestamp())
    mode = int(input['mode'])
    if mode >4 or mode < 0:
        data = {}
    else:
        data = dection.report(computer_name, mode, time_start, time_end)
    return jsonify({
            "result": {
                "data": data}})

@app.route('/process_detail', methods=['POST'])
def process_detail():
    input = request.get_json(force=True)
    id = input['_id']
    data = dection.process_detail(id)
    return jsonify({
        "result": {
            "data": data}})

@app.route('/ip-address', methods=['POST'])
def ipservice():
    input = request.get_json(force= True)
    data = ipdomain.checkIpDomain(input,1)
    return jsonify({
        "result": {
            "data": data}})

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

@app.route('/domain', methods=['POST'])
def domainservice():
    log = request.get_json(force=True)
    log_m = log['message']
    log_message = parse_message(log_m)
    input ={'domain':log_message['QueryName'].strip()}
    data = ipdomain.checkIpDomain(input,0)
    return jsonify({"machine-learing": data['status']})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9999)


