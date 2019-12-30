from elasticsearch import Elasticsearch
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from elasticsearch_dsl import Q

client = Elasticsearch(timeout = 60)
s = Search(using=client, index="winlogbeat-*")
s.source(includes=['winlog.provider_name', 'winlog.event_id'])
s.aggs.bucket('distinct_provider_names_count', 'cardinality', field='winlog.provider_name')
response = s.execute()
print ("Distinct Provider Names: %d" % (response.aggregations.distinct_provider_names_count.value))
