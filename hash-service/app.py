from flask import render_template, Flask, request
from flask import jsonify
import logging
import hash
import json

app = Flask(__name__)

@app.route('/api/check', methods=['POST'])
def check_hash():
    # hash_key = request.form["hash_key"]
    # hash_value = request.form["hash_value"]
    input = request.get_json(force=True)
    hash_input = input['hash'] # {"sha1":"d3a77e94d08f2eb9a8276f32ca16f65d1ce8b524"}
    h = json.loads(hash_input)
    hash_type = list(h.keys())[0]
    hash_value = h[hash_type].lower()
    key = hash_type.upper()

    print(f'checking type={key}, hash={hash_value}')
    result = hash.find_hash(key, hash_value)

    if result == None:
        status = "unknow"
    elif 'status' in result.keys():
        if result['status'] =='clean' :
            status = "clean"
        if result['status'] == 'malicious':
            status = "malicious"
    else:
        return jsonify({
            "result": {
                "status": "malicious",
                "info": result
            }
        })

    return jsonify({
            "result": {
                "status": status
            }
        }) 

# add hash to black or white list
@app.route('/api/add', methods=['POST'])
def request_report_url():
    hash_key = request.form["hash_key"].strip()
    hash_value = request.form["hash_value"].strip()
    status = request.form["status"].strip()

    if not hash.hash_valid_check(hash_key,hash_value):
        return jsonify({
            "result": {
                "status": "you input hash_value or hash key invalid"
                }
        })

    elif status not in ['clean', 'malicious']:
        return jsonify({
            "result": {
                "status": "you input status  invalid"
                }
        })

    result = hash.find_hash_db(hash_key, hash_value)
    if result == None:
        data = {
            hash_key : hash_value,
            "status" : status
        }
        hash.search_redis_lru_cache(hash_value, data)
        hash.user_add_db(data)
        return jsonify({
            "result": {
                "status": "Thank you. You add successfully"
                }
        })
    else:
        return jsonify({
            "result": {
                "status": "Thank you. This hash already in db"}
        })
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7979)
