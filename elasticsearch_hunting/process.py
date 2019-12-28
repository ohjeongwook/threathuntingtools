#!/usr/bin/env python
# coding: utf-8

import sys
import pprint
import datetime
import copy

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search, Q

from const import *

class ProcessTree:
    def __init__(self):
        self.ProcessMap = {}
        self.ParentMap = {}
        self.RootProcessIdList = []
        self.ProcessInfoMap={}

    def add_process_map(self, parent_guid, child_guid):
        if not parent_guid in self.ProcessMap:
            self.ProcessMap[parent_guid] = []

        self.ProcessMap[parent_guid].append(child_guid)
        self.ParentMap[child_guid]=parent_guid

    def add_root_process_id(self, process_id):
        self.RootProcessIdList.append(process_id)
        
    def find_root_pids(self):
        for process_id in self.ProcessMap.keys():
            if not process_id in self.ParentMap:
                self.RootProcessIdList.append(process_id)

    def add_process_info(self, event_data):
        if not event_data.ParentProcessGuid in self.ProcessInfoMap:
            self.ProcessInfoMap[event_data.ParentProcessGuid] = {
                'Image': event_data.ParentImage,
                'CommandLine': event_data.ParentCommandLine,
                'ProcessId': event_data.ParentProcessId
            }

        self.ProcessInfoMap[event_data.ProcessGuid] = event_data.to_dict()

    def find(self, process_name = None, process_id = None):
        traced_process_tree_list=[]
        for (process_guid, process_info) in self.ProcessInfoMap.items():
            found = False
            if process_name != None and process_info['Image'].lower().find(process_name.lower())>=0:
                found = True
            elif process_id != None and process_info['ProcessId'] == str(process_id):
                found = True

            if not found:
                continue

            traced_process_tree = ProcessTree()
            current_process_guid = process_guid            
            while current_process_guid in self.ParentMap:
                parent_process_guid = self.ParentMap[current_process_guid]
                traced_process_tree.add_process_map(parent_process_guid, current_process_guid)
                current_process_guid = parent_process_guid

            traced_process_tree.add_root_process_id(current_process_guid)

            if process_guid in self.ProcessMap:
                traced_process_tree.ProcessMap[process_guid] = copy.deepcopy(self.ProcessMap[process_guid])

            traced_process_tree.ProcessInfoMap = self.ProcessInfoMap
            traced_process_tree_list.append(traced_process_tree)

        return traced_process_tree_list

    def _print(self, process_guid, level = 0):
        if process_guid in self.ProcessInfoMap:
            prefix_str = ' ' * level
            
            if 'UtcTime' in self.ProcessInfoMap[process_guid]:
                processTime = '(%s)' % self.ProcessInfoMap[process_guid]['UtcTime']
            else:
                processTime = ""
            print('%s[%s] %s %s - %s' % (prefix_str, self.ProcessInfoMap[process_guid]['ProcessId'], processTime, self.ProcessInfoMap[process_guid]['Image'], self.ProcessInfoMap[process_guid]['CommandLine']))

        if process_guid in self.ProcessMap:
            for child_process_guid in self.ProcessMap[process_guid]:
                self._print(child_process_guid, level = level+1)

    def print(self, level = 0):
        for root_process_guid in self.RootProcessIdList:
            self._print(root_process_guid, level = 0)

class Process:
    def __init__(self, hostname = None, start_datetime = None, end_datetime = None, scan = False):
        self.Hostname = hostname
        self.Scan = scan
        
        timestamp = {}
        
        if start_datetime!=None:
            timestamp['gte'] = start_datetime

        if end_datetime!=None:
            timestamp['lt'] = end_datetime

        if len(timestamp)>0:
            self.DTRange = {'@timestamp': timestamp }
        else:
            self.DTRange = None

        self.Client = Elasticsearch()
    
    def get_default_elastic_bool_expression(self, process_id=None, process_name=None):
        elastic_bool = []
        elastic_bool.append({'match': {'winlog.provider_name': SYSMON_PROVIDER_NAME}})
        elastic_bool.append({'match': {'winlog.event_id': 1}})
        
        if self.Hostname != None and self.Hostname:
            elastic_bool.append({'match': {'host.hostname': self.Hostname}})
            
        if process_id != None:
            elastic_bool.append({'match': {'winlog.event_data.ProcessId': process_id}})
            
        if process_name != None and process_name:
            elastic_bool.append({'wildcard': {'winlog.event_data.Image': process_name}})        

        return elastic_bool
        
    def _search(self, query):
        s = Search(using=self.Client, index="winlogbeat-*").query(query)

        if self.DTRange!=None:
            s = s.filter('range', **self.DTRange)

        s.source(includes=['winlog.*'])
        s.sort('-winlog.event_data.UtcTime')

        if self.Scan:
            return s.scan()
        else:
            return s.execute().hits
        
    def find_process_by_guid(self, process_guid, find_parent = True):
        elastic_bool=self.get_default_elastic_bool_expression()

        if find_parent:
            elastic_bool.append({'match': {'winlog.event_data.ProcessGuid': process_guid}})
        else:
            elastic_bool.append({'match': {'winlog.event_data.ParentProcessGuid': process_guid}})

        query = Q({'bool': {'must': elastic_bool}})

        for hit in self._search(query):
            return hit
        
        return None

    def search(self, process_id = None, process_name = None, create_time = None, callback=None, options=None):
        elastic_bool=self.get_default_elastic_bool_expression(process_id=process_id, process_name=process_name)
        query = Q({'bool': {'must': elastic_bool}})
        query = Q({'bool': {'must': elastic_bool}})

        process_list=[]
        for hit in self._search(query):
            if callback is not None:
                callback(hit.winlog, options)
            else:
                process_list.append(hit.winlog)

        return process_list

    def find_process_trees(self, process_id = None, process_name = None, create_time = None):
        elastic_bool=self.get_default_elastic_bool_expression(process_id=process_id, process_name=process_name)        
        query = Q({'bool': {'must': elastic_bool}})

        process_tree_list=[]
        for hit in self._search(query):
            process_tree_list.append(self.get_process_tree(hit.winlog.event_data.ProcessGuid))
        return process_tree_list
            
    def _find_process_chain_by_guid(self, process_guid, find_parent = True):
        current_process_guid = process_guid
        while current_process_guid != None:
            hit = self.find_process_by_guid(current_process_guid, find_parent)

            if hit == None:
                print('No hit')
                break
                
            if find_parent:
                print('parent -> ' + hit.winlog.event_data.ParentProcessGuid)
                current_process_guid = hit.winlog.event_data.ParentProcessGuid
            else:
                print('child -> ' + hit.winlog.event_data.ProcessGuid)
                current_process_guid = hit.winlog.event_data.ProcessGuid

    def _find_process_chain(self, process_tree, process_guid, find_parent = True):
        current_process_guid = process_guid
        
        checked_process_guids={}
        while current_process_guid != None:
            if current_process_guid in checked_process_guids:
                print("_FindProcessChain - process chain loop found")
                break

            checked_process_guids[current_process_guid]=1
            hit = self.find_process_by_guid(current_process_guid, find_parent)

            if hit == None:
                break
                
            if find_parent:
                process_tree.add_process_map(hit.winlog.event_data.ParentProcessGuid, current_process_guid)
                current_process_guid = hit.winlog.event_data.ParentProcessGuid
            else:
                process_tree.add_process_map(current_process_guid, hit.winlog.event_data.ProcessGuid)
                current_process_guid = hit.winlog.event_data.ProcessGuid
                
            process_tree.add_process_info(hit.winlog.event_data)

        return current_process_guid
        
    def get_process_tree(self, process_guid):
        process_tree = ProcessTree()
        self._find_process_chain(process_tree, process_guid, find_parent = False)
        process_tree.add_root_process_id(self._find_process_chain(process_tree, process_guid, find_parent = True))

        return process_tree

    def build_tree(self):
        elastic_bool=self.get_default_elastic_bool_expression()
        query = Q({'bool': {'must': elastic_bool}})
        
        process_tree = ProcessTree()
        
        for hit in self._search(query):
            process_tree.add_process_map(hit.winlog.event_data.ParentProcessGuid, hit.winlog.event_data.ProcessGuid)
            process_tree.add_process_info(hit.winlog.event_data)
            
        process_tree.find_root_pids()
        return process_tree


if __name__=='__main__':
    process=Process()

    start_datetime = datetime.datetime.strptime('2019-05-20 19:40:00.0', '%Y-%m-%d %H:%M:%S.%f')
    end_datetime = datetime.datetime.strptime('2019-05-20 19:50:00.0', '%Y-%m-%d %H:%M:%S.%f')
    
    process = Process(hostname="NEWSTARTBASE", start_datetime=start_datetime, end_datetime=end_datetime, scan = True)
    process_tree_list = process.build_tree()
    process_tree_list.print()
