import sys

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from elasticsearch_dsl import Q

provider_name = sys.argv[1]

client = Elasticsearch()

elastic_bool = []
elastic_bool.append({'match': {'winlog.provider_name': provider_name}})
query = Q({'bool': {'must': elastic_bool}})
s = Search(using=client, index="winlogbeat-*").query(query)
s.source(includes=['winlog.event_id', 'winlog.event_data.LogString'])
s.aggs.bucket('sorted_distinct_log_strings', 'terms', field='winlog.event_data.LogString', size=900)
response = s.execute()

sorted_distinct_log_strings=sorted(response.aggregations.sorted_distinct_log_strings, key = lambda kv:(kv.doc_count, kv.key), reverse = True)
for e in sorted_distinct_log_strings:
    print("{0:50} Count: {1}".format(e.key, e.doc_count))
