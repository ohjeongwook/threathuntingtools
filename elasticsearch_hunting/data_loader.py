#!/usr/bin/env python
# coding: utf-8
# pylint: disable=unused-wildcard-import

from statistic_analysis import *

import yaml
import re
import yaml
import numpy as np
from collections import OrderedDict

class CommandLineData:
    def __init__(self):
        self.Entries = []
        self.Data = []
        self.Targets = []
        
    def load(self, filename):
        with open(filename, 'r', encoding = 'utf8') as fd:
            try:
                self.Entries = yaml.safe_load(fd)
                for detection in self.Entries:
                    
                    self.Data.append(detection['Command'])
                    if detection['Detection'] == 'Malicious':
                        self.Targets.append(1)
                    else:
                        self.Targets.append(0)
            except yaml.YAMLError as exc:
                print(exc)                

    def count_pattern(self, string, pattern):
        return string.count(pattern)

    def extract_powershell_features(self):
        features = []
        for entry in self.Entries:
            if entry['Detection'] == 'Malicious':
                detection = 1
            else:
                detection = 0

            feature = {}
            command = entry['Command']
            feature['Exe Count'] = self.count_pattern(command, '.exe') - self.count_pattern(command, 'powershell.exe')
            feature['Single Quote Count'] = self.count_pattern(command, '\'')
            feature['Pipe Count'] = self.count_pattern(command, '|')
            feature['Plus Count'] = self.count_pattern(command, '+')
            feature['Carret Count'] = self.count_pattern(command, '^')
            feature['Reference Count'] = len(re.findall('{[0-9]+}', command))
            feature['Block Count'] = len(re.findall(r'\[[^\[\]]+\]', command))
            feature['Entropy'] = Util.entropy(command)
            feature['Weight'] = entry['Weight']
            feature['Detection'] = detection

            m = re.search(r'([a-zA-Z%][^\\\\//\';]*)\.(exe|ps1|bat|cmd)', command, re.I)
            if m:
                feature['Command Entropy'] = Util.entropy(m.group(1))
            else:
                feature['Command Entropy'] = 0

            features.append(feature)

        return features

