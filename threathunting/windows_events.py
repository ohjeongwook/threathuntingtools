#!/usr/bin/env python
# coding: utf-8
# pylint: disable=unused-wildcard-import

import sys
import pprint
import datetime
import copy

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search, Q

from threathunting.const import *

class Events:
    def __init__(self, telemetry_server = 'localhost'):
        self.Client = Elasticsearch(telemetry_server)

    def dump_event_counts(self):
        s = Search(using = self.Client, index = WINLOGBEAT_INDEX)
        s.source(includes = ['winlog.provider_name', 'winlog.event_id'])
        s.aggs.bucket('distinct_provider_names', 'terms', field = 'winlog.provider_name', size = 100000)
        response = s.execute()

        sorted_distinct_provider_names = sorted(response.aggregations.distinct_provider_names, key = lambda kv:(kv.doc_count, kv.key), reverse = True)

        max_provider_name_len = 0
        for e in sorted_distinct_provider_names:
            str_len = len(e.key)
            if max_provider_name_len < str_len:
                max_provider_name_len = str_len

        fmt_str = "{0:%d} {1}" % max_provider_name_len
        for e in sorted_distinct_provider_names:
            print(fmt_str.format(e.key, e.doc_count))        

class Provider:    
    def __init__(self, telemetry_server = 'localhost', provider_name = '', hostname = '', start_datetime = None, end_datetime = None, scan = False, debug_query = False):
        self.DebugQuery = debug_query
        self.Scan = scan
        self.Client = Elasticsearch(telemetry_server)
        self.Hostname = hostname
        self.ProviderName = provider_name
        
        timestamp = {}
        
        if start_datetime != None:
            timestamp['gte'] = start_datetime

        if end_datetime != None:
            timestamp['lt'] = end_datetime

        if len(timestamp)>0:
            self.DTRange = {'@timestamp': timestamp }
        else:
            self.DTRange = None
            
    def get_default_query(self):
        elastic_bool = []
        
        if self.ProviderName:
            elastic_bool.append({'match': {'winlog.provider_name': self.ProviderName}})
        
        return elastic_bool
        
    def search(self, query, get_count = False, includes = None, size = 1000):
        s = Search(using = self.Client, index = WINLOGBEAT_INDEX).query(query)
        if self.DTRange != None:
            s = s.filter('range', **self.DTRange)

        if includes == None:
            includes = ['winlog.provider_name', 'winlog.event_id']

        s.source(includes = includes)

        if get_count:
            return s.count()

        if self.Scan:
            return s.scan()
        else:
            s = s[0:size]
            return s.execute().hits

        return None
        
    def get_count(self, query):
        return self.search(query, get_count = True)

    def get_event_counts(self, event_id = None):
        elastic_bool = self.get_default_query()
           
        if event_id != None:
            elastic_bool.append({'match': {'winlog.event_id': event_id}})

        return self.get_count(Q({'bool': {'must': elastic_bool}}))
    
    def get_grouped_event_counts(self, event_id = None):
        elastic_bool = self.get_default_query()
           
        if event_id != None:
            elastic_bool.append({'match': {'winlog.event_id': event_id}})

        return self.get_count(Q({'bool': {'must': elastic_bool}}))

    def get_event_id_counts(self):
        elastic_bool = self.get_default_query()

        query = Q({'bool': {'must': elastic_bool}})
        s = Search(using = self.Client, index = WINLOGBEAT_INDEX).query(query)
        if self.DTRange != None:
            s = s.filter('range', **self.DTRange)
        s.source(includes = ['winlog.event_id', 'winlog.event_data.LogString'])
        s.aggs.bucket('distinct_event_ids', 'terms', field = 'winlog.event_id', size = 1000)
        response = s.execute()

        return sorted(response.aggregations.distinct_event_ids, key = lambda kv:(kv.doc_count, kv.key), reverse = True)
    
    def print_event_id_counts(self):
        print("{0:50} {1}".format("Event ID", "Count"))
        for e in self.get_event_id_counts():
            print("{0:50} {1}".format(e.key, e.doc_count))

    def query_events(self, event_id = None, event_data_name = None, event_data_value = None, process_id = None, process_guid = None, size = 1000):
        elastic_bool = self.get_default_query()
       
        if self.Hostname != None:
            elastic_bool.append({'match': {'host.hostname': self.Hostname}})

        if event_id != None:
            elastic_bool.append({'match': {'winlog.event_id': event_id}})

        if event_data_name:
            field_name = 'winlog.event_data.' + event_data_name
            elastic_bool.append({'match': {field_name: event_data_value}})
            
        if process_id != None:
            # winlog.process.pid/winlog.event_data.ProcessId
            pid_match_query = {
                "multi_match" : {
                    "query":      str(process_id), 
                    "type":       "best_fields", 
                    "fields":     [ "winlog.process.pid", "winlog.event_data.ProcessId", "winlog.user_data.ProcessId" ], 
                    "operator":   "and" 
                }
            }
            
            elastic_bool.append(pid_match_query)

        if process_guid != None:
            elastic_bool.append({'match': {'winlog.event_data.ProcessGuid': event_data_value}})

        return self.search(Q({'bool': {'must': elastic_bool}}))

    def dump_events(self, event_id = None, print_event_meta_data = False, call_back = None):
        elastic_bool = self.get_default_query()
       
        if event_id != None:
            elastic_bool.append({'match': {'winlog.event_id': event_id}})

        for hit in self.search(Q({'bool': {'must': elastic_bool}})):
            if call_back != None:
                call_back(hit)
            else:
                print('* Event ID: %d' % (hit.winlog.event_id))                
                if print_event_meta_data:
                    pprint.pprint(hit.to_dict())
                else:
                    try:
                        pprint.pprint(hit.winlog.event_data.to_dict())
                    except:
                        pprint.pprint(hit.to_dict())

    def aggregate_by_event_data(self, event_id = None, event_data_name = "Image", sub_event_data_name = None, bucket_size = 1000, sub_bucket_size = 100, threshold = None, filter_event_data_name = '', filter_event_data_value = '', aggregate_by_hostname = False):
        elastic_bool = self.get_default_query()
       
        if event_id != None:
            elastic_bool.append({'match': {'winlog.event_id': event_id}})
            
        if filter_event_data_name:
            filter_field_name = 'winlog.event_data.' + filter_event_data_name
            elastic_bool.append({'match': {filter_field_name: filter_event_data_value}})

        query = Q({'bool': {'must': elastic_bool}})

        s = Search(using = self.Client, index = "winlogbeat-*").query(query)        
        if self.DTRange != None:
            s = s.filter('range', **self.DTRange)

        s.source(includes = ['winlog.*'])
        
        if aggregate_by_hostname:
            b = s.aggs.bucket(event_data_name, 'terms', field = 'agent.hostname', size = bucket_size)
        else:
            b = s.aggs

        b = b.bucket(event_data_name, 'terms', field = 'winlog.event_data.' + event_data_name, size = bucket_size)
        if threshold:
            # https://github.com/ongr-io/ElasticsearchDSL/blob/master/docs/Aggregation/Pipeline/BucketSelector.md
            # https://elasticsearch-dsl.readthedocs.io/en/latest/search_dsl.html
            threshold_bucket_name = event_data_name+"_counts"
            b.bucket(threshold_bucket_name, 'cardinality', field = '@timestamp')
            b.pipeline('threshold_bucket_selector', 'bucket_selector', buckets_path = { "counts": threshold_bucket_name}, script = 'params.counts > %d' % threshold)

        if sub_event_data_name:
            b.bucket(sub_event_data_name, 'terms', field = 'winlog.event_data.' + sub_event_data_name, size = sub_bucket_size)

        if self.DebugQuery:
            pprint.pprint(s.to_dict())

        response = s.execute()

        if self.Scan:
            s.scan()
        else:
            response = s.execute()
        
        return response.aggregations[event_data_name]
    
    def dump_by_event_data(self, event_id = None, event_data_name = "Image", sub_event_data_name = None, bucket_size = 1000, sub_bucket_size = 100, threshold = 100):
        print("{0:80} {1}".format(event_data_name, "Count"))

        for e in self.aggregate_by_event_data(event_id = event_id, event_data_name = event_data_name, sub_event_data_name = sub_event_data_name, bucket_size = bucket_size, sub_bucket_size = sub_bucket_size, threshold = threshold):
            print("{0:80} {1}".format(e.key, e.doc_count))
            
            if sub_event_data_name and sub_event_data_name in e:
                for bucket in e[sub_event_data_name]['buckets']:
                    print("    {0:76} {1}".format(bucket.key, bucket.doc_count))

    def dump_summary(self, print_event_meta_data = False):
        print("{0:50} {1}".format("Event ID", "Count"))
        for e in self.get_event_id_counts():
            print("{0:50} {1}".format(e.key, e.doc_count))

        self.dump_events(print_event_meta_data = print_event_meta_data)
        
    def dump_event_summary(self):
        elastic_bool = self.get_default_query()

        code2action = {}
        for hit in self.search(Q({'bool': {'must': elastic_bool}})):
            try:
                code2action[hit.event.code] = hit.event.action
            except:
                code2action[hit.event.code] = str(hit.event.to_dict())
            
        for (code, action) in code2action.items():
            print("Code: %d Action: %s" % (code, action))

class File:
    def __init__(self, telemetry_server = 'localhost', hostname = None, start_datetime = None, end_datetime = None, scan = False):
        self.Hostname = hostname
        self.Scan = scan
        self.Provider = Provider(telemetry_server, SYSMON_PROVIDER_NAME, start_datetime = start_datetime, end_datetime = end_datetime, scan = scan)
        
    def aggregate_by_image_target_filename(self):
        results = self.Provider.aggregate_by_event_data(event_id = 11, event_data_name = "Image", sub_event_data_name = "TargetFilename", bucket_size = 1000, sub_bucket_size = 100, threshold = 100)

        for target_filename in results[0]['TargetFilename']:
            print(target_filename.key, target_filename.doc_count)

        
    def aggregate_by_image(self):
        results = self.Provider.aggregate_by_event_data(event_id = 11, event_data_name = "Image", bucket_size = 1000)

        for image in results:
            print('%s: %d' % (image.key, image.doc_count))

    def aggregate_by_target_filename(self, image, size = 1000):
        # [Allow for `scan` with aggregations #580](https://github.com/elastic/elasticsearch-dsl-py/issues/580)
        filenames = []
        for hit in self.Provider.query_events(event_id = 11, event_data_name = 'Image', event_data_value = image, size = size):
            filenames.append(hit.winlog.event_data.TargetFilename)
        return filenames

