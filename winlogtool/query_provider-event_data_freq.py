import sys
import argparse

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search, Q

parser = argparse.ArgumentParser(description='Process some integers.')
parser.add_argument('-p', '--provider_name', help='Provider Name')
parser.add_argument('-i', '--event_id', type=int, help='Event ID')
parser.add_argument('-d', '--event_data', help='Event Data Name')
args = parser.parse_args()

winlog_event_data_name = 'winlog.event_data.' + args.event_data

client = Elasticsearch(timeout = 60)

elastic_bool = []
elastic_bool.append({'match': {'winlog.provider_name': args.provider_name}})

if args.event_id != None:
        elastic_bool.append({'match': {'winlog.event_id': args.event_id}})

query = Q({'bool': {'must': elastic_bool}})

s = Search(using=client, index="winlogbeat-*").query(query)
s.source(includes=[winlog_event_data_name])
s.aggs.bucket('distinct_query_name', 'terms', field=winlog_event_data_name , size=900)
response = s.execute()

sorted_distinct_query_name=sorted(response.aggregations.distinct_query_name, key = lambda kv:(kv.doc_count, kv.key), reverse = True)

max_len=0
for e in sorted_distinct_query_name:
    if len(e.key) > max_len:
        max_len = len(e.key)

fmt_str="{0:%d} Count: {1}" % (max_len)
for e in sorted_distinct_query_name:
    print(fmt_str.format(e.key, e.doc_count))
