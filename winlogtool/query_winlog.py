import sys
import json
import pprint

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search, Q

provider_name = sys.argv[1]

client = Elasticsearch(timeout = 60)

elastic_bool = []
elastic_bool.append({'match': {'winlog.provider_name': provider_name}})
query = Q({'bool': {'must': elastic_bool}})
s = Search(using=client, index="winlogbeat-*").query(query)
s.source(includes=['winlog.*'])

for hit in s.scan():
  pprint.pprint(hit.winlog.to_dict())
