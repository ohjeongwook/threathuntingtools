#!/usr/bin/env python
# coding: utf-8
# pylint: disable=unused-wildcard-import, import-error

import sys
sys.path.append(r'..')
from datetime import *
import threathunting.process

if __name__ == '__main__':
    start_datetime = datetime.strptime('2019-05-20 19:40:00.0', '%Y-%m-%d %H:%M:%S.%f')
    end_datetime = datetime.strptime('2019-05-20 19:50:00.0', '%Y-%m-%d %H:%M:%S.%f')
    
    processes = process.Processes(hostname = "NEWSTARTBASE", start_datetime = start_datetime, end_datetime = end_datetime, scan = True)
    process_trees = processes.build_tree()
    process_trees.print()
