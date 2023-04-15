import config
import json
import collections
import createTree
import time
import connection

client = connection.ESconnection
mongo = connection.mongoconnection
users_db = mongo.Users
users_collection = users_db['user']

def get_all():
  all_users = []
  users = users_collection.find({})
  for user in users:
    username = user['name']
    all_users.append({"computer_name":username,"status":0,"malicious": 0})
  return all_users

def add_db(newuser):
  users_collection.insert_one(newuser).inserted_id

def check_process(data,data1):
  for d in data1:
    if "process" in d['_source']:
      data.append(d)

def query_search(time_start, time_end, computer_name):
    query1 = json.dumps({
    "query": {
        "bool": {
            "must":[{
              "range" : {
                "@timestamp": {
                  "gte" : time_start,
                  "lt" :  time_end,
                  "format": "epoch_second"
                  }}
              },{"match": {
                  "host.hostname":{
                    "query": computer_name,
                    "minimum_should_match": "100%"
                  } }},{"match": {
                    "mitre_detect.mitre-detected": "1"
                  }}]
          }
    },"size": 10000
})
    query2 =  json.dumps({
    "query": {
        "bool": {
            "must":[{
              "range" : {
                "@timestamp": {
                  "gte" : time_start,
                  "lt" :  time_end,
                  "format": "epoch_second"
                  }}
              },{"match": {
                  "host.hostname":{
                    "query": computer_name,
                    "minimum_should_match": "100%"
                  } }},{"match": {
                    "hash_detect.result.status": "malicious"
                  }}]
          }
    },"size": 10000
})
    query3 =  json.dumps({
    "query": {
        "bool": {
            "must":[{
              "range" : {
                "@timestamp": {
                  "gte" : time_start,
                  "lt" :  time_end,
                  "format": "epoch_second"
                  }}
              },{"match": {
                  "host.hostname":{
                    "query": computer_name,
                    "minimum_should_match": "100%"
                  } }},{"match": {
                    "ml_detect.machine-learing": "malicious"
                  }}]
          }
    },"size": 10000
})
    data = []
    data1 = client.search(index = "winlogbeat-*",body = query1)
    check_process(data,data1['hits']['hits'])
    data2 = client.search(index = "winlogbeat-*",body = query2)
    check_process(data,data2['hits']['hits'])
    data3 = client.search(index = "winlogbeat-*",body = query3)
    check_process(data,data3['hits']['hits'])
    return data

def realTime(): 
  hostnames = get_all()
  time_end = int(time.time())
  time_start_active = time_end - 120
  time_start_malicous = time_end - 3600
  query = json.dumps({
    "query": {
        "bool": {
            "must":[{
              "range" : {
                "@timestamp": {
                  "gte" : time_start_active,
                  "lt" :  time_end,
                  "format": "epoch_second"
                  }}
              }]
          }
    },"size":10000,"_source": ["host"]
})
  data = client.search(index = "winlogbeat-*",body = query)
  for hostname in data['hits']['hits']:
    host = hostname['_source']
    checkhostname(host, hostnames)
  for h in hostnames:
    computer_name =  h['computer_name']
    data_malicous = query_search(time_start_malicous,time_end,computer_name)
    if len(data_malicous)>0:
      h['malicious'] = 1
  result =json.dumps({'data':hostnames}) 
  yield 'data:%s\n\n'%result

def checkhostname(hostname, hostnames):
  for i in range(len(hostnames)):
    if hostname['host']['hostname'] == hostnames[i]['computer_name'] :
      if hostnames[i]['status'] == 0:
        hostnames[i]['status'] = 1
      return

  hostnames.append({"computer_name":hostname['host']['hostname'],"status":1,"malicious":0})
  add_db(hostname['host'])

# print(realTime())


def checkguid(process,children):
  for i in range(len(children)):
    if process['_source']['process']['entity_id'] == children[i]['_source']['process']['entity_id'] and "parent" in process['_source']['process'].keys():
      try:
        if children[i]['_source']['mitre_detect']['mitre-detected'] == 1 :
          return False
      except:
        pass
      try:
        if children[i]['_source']['hash_detect']['result']['status'] == 'malicious':
          return False
      except:
        pass
      try:
        if children[i]['_source']['ml_detect']['machine-learing'] == 'malicious':
          return False
      except:
        pass
      del children[i]
      return True
    elif process['_source']['process']['entity_id'] == children[i]['_source']['process']['entity_id'] and not "parent" in process['_source']['process'].keys():
      try:
        if process['_source']['mitre_detect']['mitre-detected'] == 1 :
          del children[i]
          return True
      except:
        pass
      try:
        if process['_source']['hash_detect']['result']['status'] == 'malicious':
          del children[i]
          return True
      except:
        pass
      try:
        if process['_source']['ml_detect']['machine-learing'] == 'malicious':
          del children[i]
          return True
      except:
        pass
      return False
  return True

def search_parent_child_process(computername,pguid,mode):
  key = ""
  if mode == 0:
    key = "process.parent.entity_id"  #find children
  else:
    key = "process.entity_id"         #find parent

  query = json.dumps({
  "query": {
    "bool": {
      "must": [
        { "match": 
          { 
            "host.hostname":
            {
              "query": computername,
              "minimum_should_match":"100%"
            }  
          }
        },
        { "match": 
          { key: 
          {
             "query": pguid,
              "minimum_should_match":"100%"
          }
          }
        }
      ]
    }
  },"size": 500
})
  data = client.search(index = "winlogbeat-*",body = query)
  children=[]
  if len(data['hits']['hits']) == 0:
    return []
  for process in data['hits']['hits']:
    if checkguid(process,children):
        children.append(process)
  return children

def find_root(process):
  rootprocess = process
  while True:
    if 'parent' in rootprocess['_source']['process'].keys(): 
      computername = rootprocess['_source']['host']['hostname']
      pguid = rootprocess['_source']['process']['parent']['entity_id']
      parent = search_parent_child_process(computername,pguid,1)
      if parent:
        rootprocess = parent[0]
      else:
        return rootprocess
    else:
      return rootprocess

def dict_tree_process(process_str):
  process = search_parent_child_process(process_str['computer_name'],process_str['guid'],1)
  list_id=[]
  if len(process) == 0:
    return 
  tree_node = []
  root = find_root(process[0])
  queue = [root]
  while len(queue) > 0:
    parent = queue.pop(0)
    computername = parent['_source']['host']['hostname']
    pguid = parent['_source']['process']['entity_id']
    if pguid in list_id:
      continue
    else:
      list_id.append(pguid)
    childr = search_parent_child_process(computername,pguid,0)
    for child in childr:
      queue.append(child)
      node = (child,parent)
      tree_node.append(node)
  if len(tree_node) == 0:
    return [{"infor":root}]
  tree = createTree.Tree(list(reversed(tree_node)))
  return tree[root['_source']['process']['entity_id']]
# process_str={
# "computer_name":"Lupin",
#  "guid":"{9d06d7e3-5ff8-5f54-161a-000000000e00}"
# }
# print(dict_tree_process(process_str))
def detail(computer_name):
  query = {"hostname":computer_name}
  result = users_collection.find_one(query)
  if result:
    info = result
    del info['_id']
  else:
     return "Not Found"
  return info

def computer_detail(computer_name, time_start, time_end, eventID):
  query = json.dumps({
    "query": {
        "bool": {
            "must":[{
              "range" : {
                "@timestamp": {
                  "gte" : time_start,
                  "lt" :  time_end,
                  "format": "epoch_second"
                  }
                }
              },{"match": {
                "event.module": "sysmon"
              }},{"match": {
                  "event.code": eventID
                }
              },{"match": {
                  "host.hostname":{
                    "query": computer_name,
                    "minimum_should_match": "100%"
                  } 
                }
              }
            ]
          }
        },"_source": ["process", "file", "related",  "dns" ],
      "size": 10000
      })
  data = client.search(index = "winlogbeat-*",body = query)
  result = []
  if eventID == 1: 
      result.append({'process_create':[]})
      for doc in data["hits"]['hits']:
        if 'process' in doc['_source']:
          check_count(doc['_source']['process']['executable'], result[0]['process_create'])
  if eventID == 2: 
      result.append({'file_modify':[]})
      for doc in data["hits"]['hits']:
        if 'file' in doc['_source']:
          check_count(doc['_source']['file']['path'], result[0]['file_modify'])

  if eventID == 3:
      result.append({'network_connection':[]})
      for doc in data["hits"]['hits']:
        if "related" in doc['_source']:
          check_count(doc['_source']['related']['ip'][1], result[0]['network_connection'])

  if eventID == 11:
      result.append({'file_create':[]})
      for doc in data["hits"]['hits']:
        if "file" in doc['_source']:
          check_count(doc['_source']['file']['path'], result[0]['file_create'])

  if eventID == 22:
      result.append({'dns_query':[]})
      for doc in data["hits"]['hits']:
        if "dns" in doc['_source']:
          check_count(doc['_source']['dns']['question']['name'], result[0]['dns_query'])
  return result


def report(computer_name, mode, time_start, time_end):
  listid = [1,2,3,11,22]
  eventID = listid[mode]
  result = computer_detail(computer_name, time_start, time_end, eventID)
  return result

def check_count(name, listdic):
  key = 'key'
  count = 'count'
  for i in range(len(listdic)):
    if name == listdic[i][key]:
      listdic[i][count] = listdic[i][count] +1
      return 
  listdic.append({key:name,count:1})
      
def process_detail(id):
  query = json.dumps({
    "query": {
      "match": {
        "_id":{"query": id,"minimum_should_match": 1} 
    }}
})
  data = client.search(index="winlogbeat-*",body = query)
  return data["hits"]['hits'] if data["hits"]['hits'] else None 


