import requests
data = {"hash_key" : "MD5", "hash_value" : "99b4befaf30d48110daa05d440c08e71"}
url = "http://192.168.1.3/api/check"
url_add = "http://192.168.1.3/api/add"
r =requests.post(url = url, data = data)
print(r.text)
data_add = {
        "hash_key" : "MD5",
        "hash_value" : "99b4befaf30d48110daa05d440c08e73", 
        "status" : "clean"
}
t =requests.post(url = url_add, data= data_add)
print (t.text)