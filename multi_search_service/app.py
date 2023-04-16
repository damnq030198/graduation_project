import flask
from flask import request, jsonify

from elasticsearch import Elasticsearch
import config
import query
import urllib.parse as urlparse
from urllib.parse import parse_qs
from flask_cors import CORS

es = Elasticsearch([config.SERVER])

app = flask.Flask(__name__)
CORS(app)

LIST_FIELDS = [
    'dns.question.name.keyword',
    'destination.port',
    'destination.ip.keyword',
    'event.code'
]

def elashticsearch_query(computer_name, process_name, field):
    q = query.QUERY_INFOR_DOMAIN_IP_PORT
    q['aggs']['COMPUTER_NAME']['filter']['term']['host.name.keyword'] = computer_name
    q['aggs']['COMPUTER_NAME']['aggs']['PROCESS_NAME']['filter']['term']['process.name.keyword'] = process_name
    q['aggs']['COMPUTER_NAME']['aggs']['PROCESS_NAME']['aggs']['FIELD']['terms']['field'] = field
    res = es.search(index="winlogbeat*", body=q)
    return res

def count_domain_per_minute(computer_name, process_name, time_from, time_to, field):
    if process_name != None:
        q = query.QUERY_COUNT_PER_MI
        q['query']['bool']['filter']['range']['@timestamp']['gte'] = time_from
        q['query']['bool']['filter']['range']['@timestamp']['lte'] = time_to
        q['aggs']['COMPUTER_NAME']['filter']['term']['host.name.keyword'] = computer_name
        q['aggs']['COMPUTER_NAME']['aggs']['PROCESS_NAME']['filter']['term']['process.name.keyword'] = process_name
        q['aggs']['COMPUTER_NAME']['aggs']['PROCESS_NAME']['aggs']['myDateHistogram']['aggs']['FIELD']['terms']['field'] = field
    else:
        q = query.QUERY_COUNT_PER_MI_EXCLUCE
        q['query']['bool']['filter']['range']['@timestamp']['gte'] = time_from
        q['query']['bool']['filter']['range']['@timestamp']['lte'] = time_to
        q['aggs']['COMPUTER_NAME']['filter']['term']['host.name.keyword'] = computer_name
        q['aggs']['COMPUTER_NAME']['aggs']['myDateHistogram']['aggs']['FIELD']['terms']['field'] = field
    res = es.search(index="winlogbeat*", body=q)
    return res

def get_event_id_by_guid(guid, field):
    q = query.QUERY_GET_ALL_EVENT_ID_BY_GUID
    q['aggs']['GUID']['filter']['term']['process.entity_id.keyword'] = guid
    q['aggs']['GUID']['aggs']['FIELD']['terms']['field'] = field
    res = es.search(index="winlogbeat*", body=q)
    return res

@app.route('/_count_per_mi', methods=['GET'])
def COUNT_FIELD_PER_MI():
    computer_name = request.args.get("computer_name")
    process_name = request.args.get("process_name")
    time_from = request.args.get('time_from')
    time_to = request.args.get('time_to')
    field_count = request.args.get('field_count')
    field_count = int(field_count)
    response = count_domain_per_minute(computer_name, process_name, time_from, time_to, LIST_FIELDS[field_count])
    return jsonify({
        'result': response["aggregations"]
    })

@app.route('/_domain', methods=['POST'])
def GET_DOMAIN_COUNT():
    json_data = request.get_json(force=True)
    print(json_data)
    computer_name = json_data['computer_name']
    process_name = json_data['process_name']
    response = elashticsearch_query(computer_name, process_name, LIST_FIELDS[0])
    return jsonify({
        'result': response["aggregations"]
    })

@app.route('/_port', methods=['POST'])
def GET_PORT_COUNT():
    json_data = request.get_json(force=True)
    print(json_data)
    computer_name = json_data['computer_name']
    process_name = json_data['process_name']
    response = elashticsearch_query(computer_name, process_name, LIST_FIELDS[1])
    return jsonify({
        'result': response["aggregations"]
    })

@app.route('/_get_aggs_field_by_GUID', methods=['GET'])
def GET_ALL_EVENT_ID_BY_GUID():
    try:
        guid = request.args.get("_guid")
        field_count = request.args.get('_field_count')
        field_count = int(field_count)
        response = get_event_id_by_guid(guid, LIST_FIELDS[field_count])
        return jsonify({
            'result': response["aggregations"]
        })
    except:
        return jsonify({
            'rs': 'gui query sai roi, dm nhin lai di :('
        })

@app.route('/_ip', methods=['POST'])
def GET_IP_COUNT():
    json_data = request.get_json(force=True)
    print(json_data)
    computer_name = json_data['computer_name']
    process_name = json_data['process_name']
    response = elashticsearch_query(computer_name, process_name, LIST_FIELDS[2])
    return jsonify({
        'result': response["aggregations"]
    })



if __name__ == "__main__":
    app.run(host='0.0.0.0', port=6868)