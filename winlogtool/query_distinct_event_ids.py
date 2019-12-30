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
s.aggs.bucket('distinct_event_ids', 'terms', field='winlog.event_id', size=1000)
response = s.execute()

sorted_distinct_distinct_event_ids=sorted(response.aggregations.distinct_event_ids, key = lambda kv:(kv.doc_count, kv.key), reverse = True)
for e in sorted_distinct_distinct_event_ids:
    print("{0:50} {1}".format(e.key, e.doc_count))
