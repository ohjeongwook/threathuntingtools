#!/usr/bin/env python
# coding: utf-8
# pylint: disable=unused-wildcard-import

import sys
import traceback

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from elasticsearch_dsl import Q

from threathunting.const import *

class QueryUtil:
    def __init__(self, telemetry_server = 'localhost'):
        self.Client = Elasticsearch(telemetry_server)

    def query_event_ids(self):
        elastic_bool = []
        elastic_bool.append({'match': {'winlog.provider_name': MICROSOFT_WINDOWS_DNSCLIENT_PROVIDER_NAME}})
        query = Q({'bool': {'must': elastic_bool}})
        s = Search(using = self.Client, index = "winlogbeat-*").query(query)
        s.source(includes = ['winlog.provider_name', 'winlog.event_id'])

        count = s.count()
        print("Count: %d" % (count))

        event_ids = {}
        i = 0

        try:
            for hit in s.scan():
                print('%d. %d' % (i, hit.winlog.event_id))
                if not hit.winlog.event_id in event_ids:
                    event_ids[hit.winlog.event_id] = 1
                    print("%s: %d" % (hit.winlog.provider_name, hit.winlog.event_id))
                else:
                    event_ids[hit.winlog.event_id] += 1  
                    
                i += 1
        except:
            traceback.print_exc()

    def query_distinct_event_ids(self):
        elastic_bool = []
        elastic_bool.append({'match': {'winlog.provider_name': MICROSOFT_WINDOWS_DNSCLIENT_PROVIDER_NAME}})
        query = Q({'bool': {'must': elastic_bool}})
        s = Search(using = self.Client, index = "winlogbeat-*").query(query)
        s.source(includes = ['winlog.event_id', 'winlog.event_data.LogString'])
        s.aggs.bucket('distinct_event_ids', 'terms', field = 'winlog.event_id', size = 1000)
        response = s.execute()

        sorted_distinct_distinct_event_ids = sorted(response.aggregations.distinct_event_ids, key = lambda kv:(kv.doc_count, kv.key), reverse = True)
        for e in sorted_distinct_distinct_event_ids:
            print("{0:50} {1}".format(e.key, e.doc_count))

    def query_query_names(self, size = 6000, descending = True):
        winlog_event_data_name = "winlog.event_data.QueryName"

        elastic_bool = []
        elastic_bool.append({'match': {'winlog.provider_name': MICROSOFT_WINDOWS_DNSCLIENT_PROVIDER_NAME}})
        query = Q({'bool': {'must': elastic_bool}})

        s = Search(using = self.Client, index = "winlogbeat-*").query(query)
        s.source(includes = [winlog_event_data_name])\
        
        if descending:
            order = 'desc'
        else:
            order = 'asc'
            
        s.aggs.bucket('distinct_query_name', 'terms', field = winlog_event_data_name, size = size, order = {'_count': order})

        response = s.execute()
        sorted_distinct_query_name = response.aggregations.distinct_query_name

        max_len = 0
        for e in sorted_distinct_query_name:
            if len(e.key) > max_len:
                max_len = len(e.key)
                
        fmt_str = "{0:%d} Count: {1}" % (max_len)
        for e in sorted_distinct_query_name:
            print(fmt_str.format(e.key, e.doc_count))

if __name__ == '__main__':
    query_util = QueryUtil()
    query_util.query_query_names()
