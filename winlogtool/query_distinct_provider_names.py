from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from elasticsearch_dsl import Q

client = Elasticsearch(timeout = 60)
s = Search(using=client, index="winlogbeat-*")
s.source(includes=['winlog.provider_name', 'winlog.event_id'])
s.aggs.bucket('distinct_provider_names', 'terms', field='winlog.provider_name', size=100000)
response = s.execute()

sorted_distinct_provider_names=sorted(response.aggregations.distinct_provider_names, key = lambda kv:(kv.doc_count, kv.key), reverse = True)

max_provider_name_len = 0
for e in sorted_distinct_provider_names:
    str_len = len(e.key)
    if max_provider_name_len < str_len:
        max_provider_name_len = str_len

fmt_str="{0:%d} {1}" % max_provider_name_len
for e in sorted_distinct_provider_names:
    print(fmt_str.format(e.key, e.doc_count))
