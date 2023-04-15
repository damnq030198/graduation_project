import redis
import requests
import config
import json
import string
from pymongo import MongoClient
from bs4 import BeautifulSoup

session = requests.Session()
client = MongoClient(config.MONGO_CONECTION)
mongodb = client.VirusShare
hash_collection = mongodb['hash']
red = redis.StrictRedis(host='localhost', port=6379, db=1)

# supported hash
MD5, SHA1, SHA256 = 'MD5', 'SHA1', 'SHA256'


def find_hash_db(key, value):
    result = hash_collection.find_one({key: value}, {'_id': False})
    return result


def search_virus_share(key,hash):
    session.headers = {'User-Agent': config.USER_AGENT}
    data = {"search": hash, "start": "0"}
    response = session.post(url="https://virusshare.com/search", data=data)
    if "login" in response.text:
        auth = {"username": config.VIRUSSHARE_USERNAME,
                "password": config.VIRUSSHARE_PASSWORD}
        response = session.post(
            url="https://virusshare.com/processlogin", data=auth)
        response = session.post(
            url="https://virusshare.com/search", data=data)
    if "No results" in response.text :
        result = {key:hash, "status":"unknow"}
        return result
    elif "No Detections" in response.text or "Benign" in response.text:
        result = {key:hash, "status":"clear"}
        return result
    soup = BeautifulSoup(response.content, "html.parser")
    hash_dictionary = analysis_virus_share(soup)
    return hash_dictionary


def add_hash_db(hash_dictionary):
    _id = hash_collection.insert_one(hash_dictionary).inserted_id

def analysis_virus_share(soup):
    tables = soup.findAll("table")
    flag = 0
    hash_dictionary = {}
    for table in tables:
        flag = flag +1
        rows = table.findAll("tr")
        if flag ==3:
            hash_dictionary["Detections"] = []
            for i in range(len(rows)):
                if i == len(rows)-1:
                    pass
                else:
                    key = str(rows[i].findAll("td")[0].contents[0]).strip()
                    value = str(rows[i].findAll("td")[1].contents[0]).strip()
                    hash_dictionary["Detections"].append({key:value})
        if flag == 4:
            hash_dictionary["ExIF_Data"] = []
            for i in range(len(rows)):
                key = str(rows[i].findAll("td")[0].contents[0]).strip()
                if len(rows[i].findAll("td")[1].contents) == 1:
                    value = str(rows[i].findAll("td")[1].contents[0]).strip()
                else:
                    value = ""
                hash_dictionary["ExIF_Data"].append({key:value})
    if flag == 0:
        return None
    rows = soup.findAll('tr')
    for i in range(len(rows)):
        cells = rows[i].findAll('td')
        if len(cells) < 2:
            continue
        elif len(cells) == 2 and i >3:
            key = str(cells[0].contents[0]).strip()
            if key == "SSDeep":
                value = str(cells[1].find('span').contents[0]).strip()
                hash_dictionary[key] = value
            elif key == "\n":
                continue
            elif key == 'TrID':
                value = ''
                for i in range(0,len(cells[1].contents),2):
                    value = value + cells[1].contents[i] + "\n"
            else:
                value = str(cells[1].contents[0]) 
            hash_dictionary[key] = value
        else:
            if "Detections" in str(cells[0]):
               break
    hash_dictionary['status'] = 'malicious'
    return hash_dictionary


def search_redis_lru_cache(hash):
    result = red.get(hash)
    if result == None:
        return False, None
    return True, json.loads(result.decode())


def add_redis_lru_cache(hash, value):
    red.set(hash, json.dumps(value))
    if not value:
        red.expire(hash, config.TIMEOUT)


def hash_valid_check(hash_type, hash_value):
    for c in hash_value:
        if c not in string.hexdigits:
            return False
    if hash_type == MD5:
        return len(hash_value) == 32
    if hash_type == SHA256:
        return len(hash_value) == 64
    if hash_type == SHA1:
        return len(hash_value) == 40
    return False


def find_hash(hash_type, hash):
    if not hash_valid_check(hash_type, hash):
        print('is not a valid hash')
        return None
    print('is a valid hash')
    found, result = search_redis_lru_cache(hash)
    if not found:
        print('not found in cache')
        result = find_hash_db(hash_type, hash)
        if not result:
            print('not found in db')
            result = search_virus_share(hash_type, hash)
            print(result)
            if result:
                add_hash_db(result)
        
        if result is not None and '_id' in result.keys():
            del result['_id']
        add_redis_lru_cache(hash, result)
    return result

def user_add_db(hash_key, hash_value, status, user='user'):
    user_dictionary = {}
    user_dictionary[hash_key] = hash_value
    user_dictionary['status'] = status
    user_dictionary['user'] = user
    _id = hash_collection.insert_one(user_dictionary).inserted_id

