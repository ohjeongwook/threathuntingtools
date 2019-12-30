#!/usr/bin/env python
# coding: utf-8
# pylint: disable=unused-wildcard-import

import pprint
import traceback
import datetime
from datetime import timedelta
import sqlite3

from yaml import load, dump
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

from theathunting.windows_events import *
import theathunting.process
import theathunting.powershell
       
class ProcessQuery:
    def __init__(self, telemetry_server, hostname, start_datetime, end_datetime):
        self.SqliteConn = None
        self.TableName = "process_create"
        self.StartDateTime = start_datetime
        self.EndDateTime = end_datetime
        self.TelemetryServer = telemetry_server
        self.Process = process.Processes(telemetry_server = telemetry_server, start_datetime = self.StartDateTime, end_datetime = self.EndDateTime, scan = True)

    def open_sqlite_database(self, filename):
        try:
            self.SqliteConn = sqlite3.connect(filename)
        except sqlite3.Error as e:
            print(e)
        
    def create_table(self, field_names):
        self.FieldNames = []
        field_create_table_lines = []
        for field_name in field_names:
            normalized_field_name = field_name.replace('.', '_').lower()
            self.FieldNames.append(normalized_field_name)
            field_create_table_lines.append('%s TEXT' % normalized_field_name)

        create_table_sql = """
            CREATE TABLE """ + self.TableName + """ (
                id INTEGER PRIMARY KEY, 
        """ + ', \n'.join(field_create_table_lines) + ")"
        
        try:
            c = self.SqliteConn.cursor()
            c.execute(create_table_sql)
        except:
            traceback.print_exc()
        
    def insert_data(self, fields):
        cur = self.SqliteConn.cursor()
        
        field_str = ', '.join(self.FieldNames)
        mark_string = ''
        for i in range(0, len(self.FieldNames), 1):
            if mark_string:
                mark_string += ', '
            mark_string += '?'

        insert_statement = '''INSERT INTO %s(%s) VALUES(%s) ''' % (self.TableName, field_str, mark_string)
        
        cur.execute(insert_statement, fields)
        return cur.lastrowid

    def print_winlog(self, winlog, options):
        debug = False
        print(' = '*80)
        print('Hostname: ' + winlog.computer_name)
        print('UtcTime: '+str(winlog.event_data.UtcTime))       
        print('[%s] %s' % (winlog.event_data.ParentProcessId, winlog.event_data.ParentCommandLine))
        print('\t[%s] %s' % (winlog.event_data.ProcessId, winlog.event_data.CommandLine))
        print('\tProcessId: '+str(winlog.event_data.ProcessId))
        print('')
        
        if options['enumerate_tree']:
            process_tree = self.Process.get_process_tree(winlog.event_data.ProcessGuid)
            process_tree.print()
        
        event_datetime = datetime.datetime.strptime(winlog.event_data.UtcTime, '%Y-%m-%d %H:%M:%S.%f')
        start_datetime = event_datetime - timedelta(seconds = 60)
        end_datetime = event_datetime + timedelta(seconds = 60)
        
        if options['enumerate_events']:
            provider = Provider(telemetry_server = self.TelemetryServer, hostname = winlog.computer_name, start_datetime = start_datetime, end_datetime = end_datetime, scan = True )
            hits = provider.query_events(process_id = winlog.event_data.ProcessId)
            
            if options['full_dump']:
                print('* hits')
                print('Querying process_id: '+winlog.event_data.ProcessId)
                print('-'*80)
                for hit in hits:
                    try:
                        pprint.pprint(hit.to_dict())
                    except:
                        traceback.print_exc()
                print('-'*80)
                print('')
            else:
                for hit in hits:
                    try:
                        if debug:
                            if hit.winlog.provider_name == SYSMON_PROVIDER_NAME:
                                if hit.winlog.event_id in (1, 3, 7, 11, 12, 13, 17, 18):
                                    continue
                            elif hit.winlog.provider_name == MICROSOFT_WINDOWS_POWERSHELL_PROVIDER_NAME:
                                if hit.winlog.event_id in (4104, 40961, 53504, 40962, 4102):
                                    continue

                        print('>> %s %s (%d)' % (hit.winlog.provider_name, hit.winlog.task, hit.winlog.event_id))
                        
                        print_full_dump = False
                        if hit.winlog.provider_name == SYSMON_PROVIDER_NAME:
                            if hit.winlog.event_id == 1:
                                pass
                            elif hit.winlog.event_id == 3:
                                print('\t%s:%s' % (hit.winlog.event_data.DestinationIp, hit.winlog.event_data.DestinationPort))
                            elif hit.winlog.event_id == 7:
                                print('\t%s' % hit.winlog.event_data.ImageLoaded)
                            elif hit.winlog.event_id == 11:
                                print('\t%s' % hit.winlog.event_data.TargetFilename)
                            elif hit.winlog.event_id in (12, 13):
                                print('\t%s' % hit.winlog.event_data.TargetObject)
                            elif hit.winlog.event_id == 17:
                                print('\t%s - %s' % (hit.winlog.event_data.Image, hit.winlog.event_data.PipeName))
                            elif hit.winlog.event_id == 18:
                                print('\t%s - %s' % (hit.winlog.event_data.Image, hit.winlog.event_data.PipeName))
                                
                        elif hit.winlog.provider_name == MICROSOFT_WINDOWS_POWERSHELL_PROVIDER_NAME:
                            if hit.winlog.event_id == 4104: # Execute a Remote Command
                                print('\t%s' % hit.winlog.event_data.ScriptBlockText)
                        elif hit.winlog.provider_name == MICROSOFT_WINDOWS_DNSCLIENT_PROVIDER_NAME:
                            #if hit.winlog.event_id == 3020:
                            print('\t%s' % hit.winlog.event_data.QueryName)
                                
                        if print_full_dump:
                            print('-'*80)
                            try:
                                pprint.pprint(hit.to_dict())
                            except:
                                traceback.print_exc()                            
                            print('-'*80)
                    except:
                        traceback.print_exc()

    def process_winlog(self, winlog, options):
        if options['output_filename']:
            if options['output_file_type'] in ('yml'):
                if options['field_name_array']:
                    current_search_results = []
                    for fields in options['field_name_array']:
                        try:
                            current_field = winlog
                            for field in fields:
                                current_field = current_field[field]

                            if type(current_field) in (str, int):
                                current_search_results.append(current_field)
                            elif type(current_field) in (datetime, ):
                                current_search_results.append(str(current_field))
                            else:
                                current_search_results.append(current_field.to_dict())

                        except:
                            traceback.print_exc()
                            pprint.pprint(winlog.to_dict())
                            pass
                            
                            
                    if self.SqliteConn != None:
                        self.insert_data(current_search_results)

                    if len(current_search_results) == 1:
                        self.SearchResults.append(current_search_results[0])
                    else:
                        self.SearchResults.append(current_search_results)
                else:
                    self.SearchResults.append(winlog.to_dict())
        if options['verbose_level']>0:
            self.print_winlog(winlog, options)

    def search(self, options):
        if options['output_file_type']:
            output_file_type = options['output_file_type']
        elif options['output_filename']:
            filename, output_file_type = os.path.splitext(options['output_filename'])
            if output_file_type and len(output_file_type)>0:
                output_file_type = output_file_type[1:]

        if options['output_filename']:
            if output_file_type in ('db', 'sqlite'):
                self.open_sqlite_database(options['output_filename'])
                self.create_table(field_names)
                
        self.SearchResults = []
        self.Process.search(process_name = options['process_name'], process_id = options['process_id'], callback = self.process_winlog, options = options)
        if options['output_filename']:
            if output_file_type in ('yml'):
                with open(options['output_filename'], 'w') as fd:
                    fd.write(dump(self.SearchResults, Dumper = Dumper))
        
        if self.SqliteConn != None:
            self.SqliteConn.commit()

if __name__ == '__main__':
    import sys
    import os
    import argparse
    
    def convert_datetime_format_string(s):
        datetime_formats = ("%Y-%m-%d", '%Y-%m-%d %H', '%Y-%m-%d %H:%M', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M:%S.%f')
        
        for datetime_format in datetime_formats:
            try:
                return datetime.datetime.strptime(s, datetime_format)
            except ValueError:
                continue

        msg = "Not a valid date: '{0}'.".format(s)
        raise argparse.ArgumentTypeError(msg)

    usage = 'commands.py [-o <output sqlite db filename>] <target file/folder name>'
    parser = argparse.ArgumentParser(usage = usage)
    parser.add_argument("-F", action = "store_true", default = False, dest = "full_dump")
       
    parser.add_argument("-S", "--telemetry_server", dest = "telemetry_server", help = "Telemetry server", default = 'localhost', metavar = "TELEMETRY_SERVER")
    parser.add_argument("-H", "--hostname", dest = "hostname", help = "Hostname to search", default = '', metavar = "HOSTNAME")
    parser.add_argument("-p", "--process_name", dest = "process_name", help = "Process name pattern to search", default = '', metavar = "PROCESS_NAME")
    parser.add_argument("-i", "--process_id", metavar = "NUMBER", dest = "process_id", default = None, type = int, help = "Process ID")
    parser.add_argument("-o", "--output_filename", metavar = "OUTPUT_FILENAME", dest = "output_filename", default = None, help = "Output filename")
    parser.add_argument("-t", "--output_file_type", metavar = "OUTPUT_FILE_TYPE", dest = "output_file_type", default = '', help = "Output file type")
    parser.add_argument("-f", "--field_names", metavar = "FIELD_NAMES", dest = "field_names", default = '', help = "Field name to dump")
    
    parser.add_argument("-E", action = "store_true", default = False, dest = "enumerate_events")
    parser.add_argument("-T", action = "store_true", default = False, dest = "enumerate_tree")
    
    parser.add_argument("-v", "--verbose_level", metavar = "NUMBER", dest = "verbose_level", default = 0, type = int,
                    help = "Verbose level")
    parser.add_argument("-s", "--start_datetime", help = "The Start Date - format YYYY-MM-DD [HH[:MM[:SS[.ms]]]]", 
                    required = False, default = datetime.datetime.strptime('2019-05-01 19:40:00.0', '%Y-%m-%d %H:%M:%S.%f'), 
                    type = convert_datetime_format_string)
                    
    parser.add_argument("-e", "--end_datetime", help = "The Start Date - format YYYY-MM-DD [HH[:MM[:SS[.ms]]]]", 
                    required = False, default = datetime.datetime.now(), type = convert_datetime_format_string)

    args = parser.parse_args()

    print('* Query Processes:')
    print('\tHostname: ' + str(args.hostname))
    print('\tStart DateTime: ' + str(args.start_datetime))
    print('\tEnd DateTime: ' + str(args.end_datetime))
    pprint.pprint(vars(args))

    process_query = ProcessQuery(args.telemetry_server, args.hostname, args.start_datetime, args.end_datetime)
    
    options = vars(args)

    try:
        field_names = []
        field_name_array = []
        for field_name in options['field_names'].split(', '):
            field_names.append(field_name)
            field_name_array.append(field_name.split('.'))
        options['field_name_array'] = field_name_array
    except:
        pass
            
    process_query.search(options)
