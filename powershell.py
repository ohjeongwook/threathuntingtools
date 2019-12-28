#!/usr/bin/env python
# coding: utf-8

import re
import copy
import yaml
import pprint
import traceback

from windows_events import *
from command_line_parser import *
from string_algorithms import *
from const import *

class Telemetry:
    def __init__(self, hostname='', start_datetime = None, end_datetime = None, scan = False):
        self.PowerShellProvider = Provider(MicrosoftWindowsPowerShell, hostname=hostname, start_datetime=start_datetime, end_datetime=end_datetime, scan = scan )
        self.ScriptBlocks=[]

    def DumpSummary(self):
        print("* Event Summary:")
        self.PowerShellProvider.DumpEventSummary()
        print("")
        print("* Summary:")

    def GetScriptBlocks(self, call_back=None):
        return self.PowerShellProvider.DumpEvents(event_id=4104, call_back=call_back)
        
    def ProcessScriptBlock(self, hit):
        script_block_info={}
        script_block_info['Hostname'] = hit.host.hostname
        script_block_info['Timestamp'] = hit['@timestamp']
        script_block_info['Created'] = hit.event.created
        script_block_info['Winlog'] = hit.to_dict()
        
        try:
            script_block_info['Pid'] = hit.winlog.process.pid
        except:
            script_block_info['Pid'] = 0
            
        try:
            script_block_info['ScriptBlockText'] = hit.winlog.event_data.ScriptBlockText
        except:
            script_block_info['ScriptBlockText'] = ''

        self.ScriptBlocks.append(script_block_info)
        
    def Analyze(self):
        self.PowerShellProvider.DumpEvents(event_id=4104, call_back=self.ProcessScriptBlock)
        
    def DumpScriptBlocks(self):
        for script_block_info in self.ScriptBlocks:
            print('\tHostname: %s' % script_block_info['Hostname'])
            print('\tTimestamp: %s' % script_block_info['Timestamp'])
            print('\tCreated: %s' % script_block_info['Created'])
            #print('\tOpcode: %s' % script_block_info['Opcode'])
            print('\tPid: %s' % script_block_info['Pid'])
            print('\tScriptBlockText: %s' % script_block_info['ScriptBlockText'][0:50])
            print('')

    def Find(self, process_id):
        return self.PowerShellProvider.QueryEvents(event_id=None, process_id=process_id)

class Script:
    def __init__(self, script_block_id, message_total):
        self.MessageTotal = message_total
        self.MessageList = [''] * message_total
        self.Path = ''
        
    def AddMessage(self, message_number, script_block_text):
        if message_number < self.MessageTotal:
            self.MessageList[message_number] = script_block_text
        else:
            print("* Error:")
            
    def AddPath(self, path):
        self.Path = path
        
    def GetMessage(self):
        full_message = ''
        for message in self.MessageList:
            full_message += message
        return full_message

class ScriptProcessor:
    def __init__(self, start_datetime, end_datetime, scan=True):
        self.ScriptBlocks={}
        self.PowerShell = Telemetry(start_datetime=start_datetime, end_datetime=end_datetime, scan=scan)
        self.PowerShell.GetScriptBlocks(self.ConstructScriptBlock)

    def ConstructScriptBlock(self, hit):
        message_total = int(hit.winlog.event_data.MessageTotal)
        message_number = int(hit.winlog.event_data.MessageNumber) - 1

        print('ScriptBlockId: %s (%s/%s)' % (hit.winlog.event_data.ScriptBlockId, message_number, message_total))
        if not hit.winlog.event_data.ScriptBlockId in self.ScriptBlocks:
            self.ScriptBlocks[hit.winlog.event_data.ScriptBlockId] = Script(hit.winlog.event_data.ScriptBlockId, message_total)

        self.ScriptBlocks[hit.winlog.event_data.ScriptBlockId].AddMessage(message_number, hit.winlog.event_data.ScriptBlockText)

        if 'Path' in hit.winlog.event_data:
            self.ScriptBlocks[hit.winlog.event_data.ScriptBlockId].AddPath(hit.winlog.event_data.Path)

    def Dump(self, count=10):
        i=0
        for (script_block_id, powershell_script) in self.ScriptBlocks.items():
            print('='*80)
            print(powershell_script.GetMessage()[0:100])
            i+=1
            if i>=count:
                break
                
    def GetColumns(self):
        script_block_ids=[]
        script_block_text_list = []
        for (script_block_id, powershell_script) in self.ScriptBlocks.items():
            script_block_ids.append(script_block_id)
            script_block_text_list.append(powershell_script.GetMessage())

        return (script_block_ids, script_block_text_list)

class Commands:
    def __init__(self, filename = ''):
        self.Filename=filename
        self.StringMatcher=StringMatcher()
        self.ParsedResults=[]
        
        if filename:
            self.ReadSamples(self.Filename)
        
    def ReadSamples(self, filename):
        self.ParsedResults+=Util.ReadTestData(filename)
        
    def CollectPowerShellCommands(self):
        self.Commands=[]
        self.TraverseParseTree(self.ParsedResults)
        
    def Cluster(self):
        self.StringMatcher.AddStrings(self.Commands, "PowerShellCommand")
        self.StringMatcher.Analyze('PowerShellCommand', threshold = 0.7)
        self.StringMatcher.SaveSimilarityMatrix(r"data\PowerShellCommands-SimilarityMatrix.npz")
        
        self.StringMatcher.GetMatches(None)
        self.StringMatcher.GetMatchesCount()        

        self.StringMatcher.Cluster()
        self.StringMatcher.SaveClusters(r"data\PowerShellCommands-Clusters.pkl")        
        
    def TraverseParseTree(self, parsed_results, paths = [], level=0, debug=False):
        prefix=level*' '
        if type(parsed_results)==list:
            for parsed_result in parsed_results:
                self.TraverseParseTree(parsed_result, paths, level+1, debug=debug)

        elif type(parsed_results)==dict:
            for (name,value) in parsed_results.items():
                if name=='Command' and str(value).lower() in ('powershell', 'powershell.exe'):
                    if parsed_results['Argument']!=None and parsed_results['Argument']['ParseResult']!=None:
                        try:
                            if debug:
                                print('.'.join(paths + [name])+' : [' + pprint.pformat(parsed_results['Argument']['ParseResult']['String']) + ']')
                            self.Commands.append(parsed_results['Argument']['ParseResult']['String'])
                        except:
                            print(">> Exception:")
                            pprint.pprint(parsed_results)
                            
                        if debug:
                            print('')

                self.TraverseParseTree(value, paths + [name] , level+1, debug=debug)
        elif type(parsed_results)==str:
            pass
        else:
            if debug:
                print(prefix+str(type(parsed_results)))

class Detector:
    HeuristicRules=[
        {
            'Name': 'Download-DecoyDocx',
            'Patterns': 
                ['DownloadFile.*\(.*.docx\)'],
            'Debug': True
        },
        {
            'Name': 'Shellcode',
            'Patterns': 
                ['Invoke-Shellcode'],
            'Debug': False
        },
        {
            'Name': 'Shellcode-Run',
            'Patterns': 
                ['kernel32.*VirtualAlloc', 'kernel32.*CreateThread'],
            'Debug': False
        },
        {
            'Name': 'Encoded-Shellcode',
            'Patterns': 
                ['JABWAEgAWQBiACAAPQAgACcAJABIAGQAYQAgAD0AIAAnACcAWwBEAGwAbABJAG0AcABvAHIAdAAoACIAawBlAHIAbgBlAGwAMwAyAC4AZABs'],
            'Debug': True
        },
        {
            'Name': 'Taskkill-Winword',
            'Patterns': 
                ['taskkill.*Invoke-WebRequestwinword.exe'], # "powershell.exe" -WindowStyle Hidden taskkill /f /im winword.exe;
            'Debug': True
        },
        {
            'Name': 'Invoke-Expression-DeflateStream', 
            'Patterns': 
                ['Invoke-Expression.*DeflateStream.*FromBase64String'],
            'Debug': False
        },
        {
            'Name': 'Remove-Winword-Resiliency-RegKey', 
            'Patterns': 
                [r'Remove-Item.*Software\\Microsoft\\Office\\.*\\Word\\Resiliency']
            ,
            'Debug': False
        },
        {
            'Name': 'Powershell-CharArray-Encoded', 
            'Patterns': 
                [r'\[char\]', r'\[char\[\]\]', r'\[byte\[\]\]']
            ,
            'Debug': False
        },
        {
            'Name': 'DownloadFile', 
            'Patterns': 
                [r'Downloadfile', r'DownloadString', 'Invoke-WebRequest', 'http:', 'Net.WebClient', 'System.IO.Compression.GzipStream.*-Outfile.*\.exe', 'NetInvoke-WebRequest']
            ,
            'Weight': 0,
            'Debug': False
        },
        {
            'Name': 'IEX', 
            'Patterns': 
                [r'IEX']
            ,
            'Dependencies': ['DownloadFile'],
            'Debug': False
        },
        {
            'Name': 'Invoke-Item', 
            'Patterns': 
                [r'Invoke-Item']
            ,
            'Dependencies': ['DownloadFile'],
            'Debug': False
        },
        {
            'Name': 'Startup-Folder', 
            'Patterns': 
                [r'"\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup\\']
            ,
            'Dependencies': ['DownloadFile'],
            'Debug': True
        },
        {
            'Name': 'VBS', 
            'Patterns': 
                [r'.vbs']
            ,
            'Dependencies': ['DownloadFile'],
            'Debug': False
        },
        {
            'Name': 'Start-Process', 
            'Patterns': 
                [r'Start-Process']
            ,
            'Dependencies': ['DownloadFile'],
            'Debug': False
        },
        {
            'Name': 'Start-Exe', 
            'Patterns': 
                [r'Start.*\.exe']
            ,
            'Dependencies': ['DownloadFile'],
            'Debug': False
        },
        {
            'Name': 'Shellexecute', 
            'Patterns': 
                [r'Shellexecute']
            ,
            'Dependencies': ['DownloadFile'],
            'Debug': True
        },
        {
            'Name': 'RunEXE', 
            'Patterns': 
                [r'\.exe']
            ,
            'Dependencies': ['DownloadFile'],
            'Debug': False
        },
        {
            'Name': 'DownloadString-Execute', 
            'Patterns': 
                [r'-e']
            ,
            'Dependencies': ['DownloadFile'],
            'Debug': False
        },
        {
            'Name': 'WebRequest-Execute', 
            'Patterns': 
                [r'\[System.Uri\].*GetResponseStream.*-e']
            ,
            'Dependencies': ['DownloadFile'],
            'Debug': False
        },
        {
            'Name': 'EventvwrUACBypass', 
            'Patterns': 
                [r"reg.*add.*shell.*open.*eventvwr.exe"] # https://isc.sans.edu/diary/Another%2Bexample%2Bof%2Bmaldoc%2Bstring%2Bobfuscation%2C%2Bwith%2Bextra%2Bbonus%3A%2BUAC%2Bbypass/22153
            ,
            'Dependencies': ['DownloadFile'],
            'Debug': False
        },
        {
            'Name': 'localhost', 
            'Patterns': 
                [r"http://localhost"]
            ,
            'Weight': -5,
            'Debug': False
        },
        {
            'Name': 'PasteBin', 
            'Patterns': 
                [r":\/\/pastebin.com"]
            ,
            'Debug': False
        }
    ]
    
    def __init__(self):
        self.Detections=[]
    
    def Scan(self, powershell_command):
        debug=0
        detections=[]
        matched_rule_infos={}
        for heuristic_rule in self.HeuristicRules:
            for pattern in heuristic_rule['Patterns']:
                m=re.search(pattern, powershell_command)
                if m:
                    matched_rule_infos[heuristic_rule['Name']]={'Rule': heuristic_rule, 'MatchedString': m.group(0)}

        weight=0
        for (name, matched_rule_info) in matched_rule_infos.items():
            dependencies_fulfilled=True
            matched_rule=matched_rule_info['Rule']
            if 'Dependencies' in matched_rule and matched_rule['Dependencies']:
                for dependency in matched_rule['Dependencies']:
                    if not dependency in matched_rule_infos:
                        if debug>0:
                            print('>> Current rule %s and dependency %s is missing' % (name, dependency))
                            print('\t'+powershell_command)
                            print(matched_rules)

                        dependencies_fulfilled=False
                        break

            if not dependencies_fulfilled:
                continue

            if 'Weight' in matched_rule:
                weight+=matched_rule['Weight']
            else:
                weight+=1 # Default weight is 1

            if matched_rule['Debug']:
                print('>>> ' + name)
                print('\t'+powershell_command)
                print('')
                
        if weight>0:
            detection_str='Malicious'
        else:
            detection_str='Benign'

        detection={'Command': powershell_command, 
                   'Matched Rules': copy.deepcopy(matched_rule_infos), 
                   'Weight': weight,
                   'Detection': detection_str}
        self.Detections.append(detection)
    
    def DumpStatistics(self):
        detection_names={}
        weights={}
        for detection in self.Detections:    
            for detection_name in detection['Matched Rules']:
                if not detection_name in detection_names:
                    detection_names[detection_name]=1
                else:
                    detection_names[detection_name]+=1

            weight=detection['Weight']

            if not weight in weights:
                weights[weight]=1
            else:
                weights[weight]+=1

        print('# Detection Names:')
        pprint.pprint(detection_names)
        print('')

        print('# Weights:')
        pprint.pprint(weights)
        print('')
        
    def Write(self,filename):
        with open(filename, 'w') as fd:
            yaml.dump(self.Detections, fd)

