from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search

client = Elasticsearch()
s = Search(using=client, index="winlogbeat-*")
s.source(includes=['winlog.provider_name', 'winlog.event_id'])

maps={}

count=0
for hit in s.scan():
  if not hit.winlog.provider_name in maps:
    maps[hit.winlog.provider_name]={}

  if not hit.winlog.event_id in maps[hit.winlog.provider_name]:
    maps[hit.winlog.provider_name][hit.winlog.event_id]=1
  else:
    maps[hit.winlog.provider_name][hit.winlog.event_id]+=1

  count+=1

  if count%1000==0:
    print("Progress %d" % count)

for (provider_name,v) in maps.items():
  for (event_id, count) in v.items():
    print('%s: %d (%d)' % (provider_name, event_id, count))
