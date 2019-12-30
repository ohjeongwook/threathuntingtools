import sys

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from elasticsearch_dsl import Q

provider_name = sys.argv[1]

client = Elasticsearch(timeout = 60)

elastic_bool = []
elastic_bool.append({'match': {'winlog.provider_name': provider_name}})
query = Q({'bool': {'must': elastic_bool}})
s = Search(using=client, index="winlogbeat-*").query(query)
s.source(includes=['winlog.provider_name', 'winlog.event_id'])

count=s.count()
print("Count: %d" % (count))

for hit in s.scan():
  print("%s - %s: %d" % (hit['@timestamp'], hit.winlog.provider_name, hit.winlog.event_id))
