import pprint
from datetime import datetime
from elasticsearch import Elasticsearch

es = Elasticsearch(timeout = 60)

body = {
  "query": {
    "bool": {
      "must": [
        {
          "match": {
            "_index": "winlogbeat-*"
          }
        }
      ],
      "filter": []
    }
  },
  "_source": ["_id", "winlog.provider_name", "winlog.event_id" ],
  "size": 10000,
  "from": 0
}

maps={}

response = es.search(
  index='winlogbeat-*', 
  body=body)

hits=response['hits']['hits']

for hit in hits:
  winlog=hit['_source']['winlog']
  provider_name=winlog['provider_name']
  event_id=winlog['event_id']
  
  if not provider_name in maps:
    maps[provider_name]={}

  if not event_id in maps[provider_name]:
    maps[provider_name][event_id]=1
  else:
    maps[provider_name][event_id]+=1

for (provider_name,v) in maps.items():
  for (event_id, count) in v.items():
    print('%s: %d (%d)' % (provider_name, event_id, count))
