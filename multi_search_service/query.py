QUERY_COUNT_PER_MI = { "query": { "bool": { "filter": { "range": { "@timestamp": { "gte": "", "lte": "" } } } } }, "aggs": { "COMPUTER_NAME": { "filter": { "term": { "host.name.keyword": "" } }, "aggs": { "PROCESS_NAME": { "filter": { "term": { "process.name.keyword": "chrome.exe" } }, "aggs": { "myDateHistogram": { "date_histogram": { "field": "@timestamp", "time_zone": "GMT+7", "calendar_interval": "1m", "format": "yyyy-MM-dd-HH:mm" }, "aggs": { "FIELD": { "terms": { "field": "", "size": 2147483647 } } } } } } } } }, "size": 0 }
QUERY_INFOR_DOMAIN_IP_PORT = {"aggs": { "COMPUTER_NAME": { "filter": { "term": { "host.name.keyword": '' } }, "aggs": { "PROCESS_NAME": { "filter": { "term": { "process.name.keyword": '' } }, "aggs": { "FIELD": { "terms": { "field": '', "size": 2147483647 } } } } } } }, "size": 0 }
QUERY_COUNT_PER_MI_EXCLUCE = { "query": { "bool": { "filter": { "range": { "@timestamp": { "gte": "", "lte": "" } } } } }, "aggs": { "COMPUTER_NAME": { "filter": { "term": { "host.name.keyword": "" } }, "aggs": { "myDateHistogram": { "date_histogram": { "field": "@timestamp", "time_zone": "GMT+7", "calendar_interval": "1m", "format": "yyyy-MM-dd-HH:mm" }, "aggs": { "FIELD": { "terms": { "field": "", "size": 2147483647 } } } } } } }, "size": 0 }
QUERY_GET_ALL_EVENT_ID_BY_GUID = { "aggs": { "GUID": { "filter": { "term": { "process.entity_id.keyword": "" } }, "aggs": { "FIELD": { "terms": { "field": "event.code", "size": 2147483647 } } } } }, "size": 0 }
