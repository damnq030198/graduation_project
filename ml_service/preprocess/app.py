from flask import  Flask, request, Response
from flask_cors import CORS
from flask import jsonify
import machinelearning
app = Flask(__name__)
CORS(app)

@app.route('/ml', methods=['POST'])
def ml():
    input = request.get_json(force=True)
    try:
        ls = list(input['domain'].split(','))
    except:
        return jsonify({
            "result": {
                "data": "You input not valid. Please re-input"}})
    result = machinelearning.ml(ls)
    
    return jsonify({
            "result": {
                "data": result}})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=6969)