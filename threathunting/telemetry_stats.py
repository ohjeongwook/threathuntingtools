#!/usr/bin/env python
# coding: utf-8
# pylint: disable=unused-wildcard-import

from datetime import *
import pandas as pd
import pprint
import random

import matplotlib.pyplot as plt
import matplotlib.dates as mdates

is_plotly_imported = False
try:
    import plotly.plotly as py
    import plotly.graph_objs as go
    is_plotly_imported = True
except ImportError:
    pass

try:
    import seaborn as sns
except ImportError:
    pass

from threathunting.windows_events import *

class ProviderInformation:
    EVENT_NAME_MAP = {
        'Microsoft-Windows-Sysmon':
        {
            1: "Process Create", 
            2: "File creation time changed", 
            3: "Network connection detected", 
            4: "Sysmon service state changed", 
            5: "Process terminated", 
            6: "Driver loaded", 
            7: "Image loaded", 
            8: "CreateRemoteThread detected", 
            9: "RawAccessRead detected", 
            10: "Process accessed", 
            11: "File created", 
            12: "Registry object added or deleted", 
            13: "Registry value set", 
            14: "Registry object renamed", 
            15: "File stream created", 
            16: "Sysmon config state changed", 
            17: "Pipe Created", 
            18: "Pipe Connected", 
            19: "WmiEventFilter activity detected", 
            20: "WmiEventConsumer activity detected", 
            21: "WmiEventConsumerToFilter activity detected", 
            255: "Error report"
        }
    }
    @staticmethod
    def get_event_id_name(provider_name, event_id):
        if provider_name in ProviderInformation.EVENT_NAME_MAP:
            if event_id in ProviderInformation.EVENT_NAME_MAP[provider_name]:
                return ProviderInformation.EVENT_NAME_MAP[provider_name][event_id]
        return ''        
        
class TelemetryStats:
    def __init__(self, telemetry_server, provider_name, start_datetime, end_datetime, interval, use_plotly = False):
        self.ProviderName = provider_name
        self.StartDateTime = start_datetime
        self.EndDateTime = end_datetime
        self.Interval = interval
        self.TelemetryServer = telemetry_server
        
        if not is_plotly_imported:
            self.UsePlotLy = False
        else:
            self.UsePlotLy = use_plotly

    def get_event_counts(self, event_id = None):
        event_id_counts = []
       
        start_datetime = self.StartDateTime
        while start_datetime < self.EndDateTime:
            end_datetime = start_datetime + self.Interval
            provider = Provider(self.TelemetryServer, self.ProviderName, start_datetime = start_datetime, end_datetime = end_datetime)
            total_event_counts = provider.get_event_counts()
            event_counts = provider.get_event_counts(event_id = event_id)

            if total_event_counts == 0:
                percentage = 0
            else:
                percentage = event_counts / total_event_counts

            event_id_counts.append([start_datetime, event_counts, percentage])
            start_datetime = end_datetime
            
        df = pd.DataFrame(event_id_counts, columns =['StartDate', 'Count', 'Percentage']) 
        return df

    def get_event_counts_list(self):
        event_id_counts_list = []
       
        start_datetime = self.StartDateTime
        while start_datetime < self.EndDateTime:
            end_datetime = start_datetime + self.Interval
            provider = Provider(self.TelemetryServer, self.ProviderName, start_datetime = start_datetime, end_datetime = end_datetime)
            event_id_counts = {}
            for count in provider.get_event_id_counts():
                event_id = int(count['key'])
                event_name = ProviderInformation.get_event_id_name(self.ProviderName, event_id)
                
                if not event_name:
                    event_name = 'Event ID ' + count['key']
                event_id_counts[event_name] = count['doc_count']
                
            event_id_counts['StartDate'] = start_datetime
            event_id_counts_list.append(event_id_counts)
            start_datetime = end_datetime
            
        df = pd.DataFrame(event_id_counts_list) 

        print(df)
        return df
    
    def plot_event_counts(self, event_id = None, y = 'Count'):
        df = self.get_event_counts(event_id)

        if self.UsePlotLy:
            data = [go.Bar(x = df.StartDate, 
                        y = df.Count)]
            py.iplot(data, filename = 'bar')
        else:
            ax = df.plot(kind = 'bar', x = 'StartDate', y = y, color = 'red', figsize = (20, 10), fontsize = 12, legend = False)
            ax.set_xlabel("Hours", fontsize = 12)
            ax.set_ylabel("Hits", fontsize = 16)
            labels = ax.get_xticklabels()
            for i in range(0, len(labels), 1):
                if i%20 != 0:
                    labels[i] = ''
            ax.set_xticklabels(labels)
            plt.show()
            
    def draw_stacked_graph(self, df, x = 'StartDate'):
        # https://pandas.pydata.org/pandas-docs/stable/reference/api/pandas.DataFrame.plot.html
        try:
            pal = sns.color_palette("deep").as_hex() + sns.color_palette("bright").as_hex()
        except:
            pal = ["#C2185B", "#F8BBD0", "#E91E63", 
                   "#FFF22F", "#7C4DFF", "#212121", 
                   "#757575", "#BDBDBD", "#E64A19", 
                   "#FFCCBC", "#8BC34A", "#AFB42B", 
                   "#FF5722", "#5D4037", "#795548"]
            random.shuffle(pal)

        ax = df.plot(kind = 'bar', 
                     x = x, 
                     figsize = (20, 10), 
                     color = pal, 
                     fontsize = 12, 
                     legend = True, 
                     stacked = True)

        ax.set_xlabel("Days", fontsize = 15)
        ax.set_ylabel("Counts", fontsize = 16)

        # https://matplotlib.org/3.1.0/gallery/text_labels_and_annotations/date.html
        ax.format_xdata = mdates.DateFormatter('%Y-%m-%d')
        plt.show()
        
    def draw_event_counts_graph(self):    
        df = self.get_event_counts_list()
        self.draw_stacked_graph(df)

    def group_events(self, event_id, data_name = 'Image', aggregate_by_hostname = False, top_n = 0):
        provider = Provider(self.TelemetryServer, self.ProviderName, start_datetime = self.StartDateTime, end_datetime = self.EndDateTime)
        result = provider.aggregate_by_event_data(event_id = event_id, event_data_name =data_name, aggregate_by_hostname = aggregate_by_hostname)

        if aggregate_by_hostname:
            for host_info in result:
                print("{0:80} {1}".format(host_info.key, host_info.doc_count))
                print("\t{0:80} {1}".format(data_name, "Count"))
                i = 0
                for e in host_info[data_name]:
                    if top_n != 0 and i>top_n:
                        break
                    print("\t{0:80} {1}".format(e.key, e.doc_count))
                    i += 1
                print('')
        else:
            print("{0:80} {1}".format(data_name, "Count"))
            i = 0
            for e in result:
                if top_n != 0 and i>top_n:
                    break
                print("{0:80} {1}".format(e.key, e.doc_count))
                i += 1

