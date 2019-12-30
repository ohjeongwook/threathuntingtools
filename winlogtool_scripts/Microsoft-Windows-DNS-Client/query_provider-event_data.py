import sys

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from elasticsearch_dsl import Q

provider_name = sys.argv[1]

client = Elasticsearch()

elastic_bool = []
elastic_bool.append({'match': {'winlog.provider_name': provider_name}})
elastic_bool.append({'match': {'winlog.event_id': 3010}})
query = Q({'bool': {'must': elastic_bool}})

s = Search(using=client, index="winlogbeat-*").query(query)
s.source(includes=['winlog.event_data.QueryName'])
s.aggs.bucket('distinct_query_name', 'terms', field='winlog.event_data.QueryName', size=900)
response = s.execute()

sorted_distinct_query_name=sorted(response.aggregations.distinct_query_name, key = lambda kv:(kv.doc_count, kv.key), reverse = True)
for e in sorted_distinct_query_name:
    print("{0:50} Count: {1}".format(e.key, e.doc_count))
