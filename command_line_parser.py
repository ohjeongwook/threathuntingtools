#!/usr/bin/env python
# coding: utf-8

# In[4]:


import traceback

import yaml

class Util:
    @staticmethod
    def print(parsed_results, level=0):
        prefix=level*' '
        if type(parsed_results)==list:
            for parsed_result in parsed_results:
                Util.print(parsed_result, level+1)

        elif type(parsed_results)==dict:
            for (name,value) in parsed_results.items():
                if type(value)==str:
                    print(prefix+'* '+name+': '+value)
                else:
                    print(prefix+'+ '+name+':')
                    Util.print(value, level+1)
        elif type(parsed_results)==str:
            print(prefix+': '+parsed_results)
        else:
            print(prefix+str(type(parsed_results)))

    @staticmethod
    def read_test_data(filename, file_type='yml', rerun_parser=False):
        parsed_results=[]
        with open(filename, 'r', encoding='utf8') as fd:
            if file_type=='yml':
                try:                
                    for parsed_result in yaml.safe_load(fd):
                        if rerun_parser:
                            command_line_itertor=CommandLineItertor(parsed_result['CommandLine']['String'])      
                            cmd_line_parser=CommandLineParser(command_line_itertor, parsers=("cmd"))
                            parsed_result=cmd_line_parser.parse()       
                        parsed_results.append(parsed_result)       
                except yaml.YAMLError as exc:
                    print(exc)
            elif file_type=='json':                    
                for parsed_result in json.loads(fd.read()):
                    if rerun_parser:
                        command_line_itertor=CommandLineItertor(parsed_result['CommandLine']['String'])
                        cmd_line_parser=CommandLineParser(command_line_itertor, parsers=("cmd"))
                        parsed_result=cmd_line_parser.parse()
                    parsed_results.append(parsed_result)

        return parsed_results
    
    @staticmethod
    def write_test_data(filename, parsed_results):
        with open(filename, 'w') as fd:
            yaml.dump(parsed_results, fd)        


# In[8]:


# http://www.windowsinspired.com/understanding-the-command-line-string-and-arguments-received-by-a-windows-program/
# http://www.windowsinspired.com/how-a-windows-programs-splits-its-command-line-into-individual-arguments/
from lark import Lark, tree, lexer, Transformer

from enum import Enum
class State(Enum):
    InterpretSpecialChars=0
    IgnoreSpecialChars=1
    
class ParsingMode(Enum):
    CommandLineToArgvW=0
    ArgV=1
    PowerShell=2

class CommandLineItertor:
    DelimiterCharacters=(' ', '\t')
    CommandSeparator=('&', '|')
    def __init__(self, input_string, starts_with_command = True, parsing_mode = ParsingMode.CommandLineToArgvW):
        self.InputString = input_string
        self.InputStringIndex=0
        self.StartsWithCommand=starts_with_command
        self._ParsingMode=parsing_mode
        self.QuoteStart=False
        self.QuotesCount=0
        self.InterpretState=State.InterpretSpecialChars
        self.Arguments=[]
        
    def set_parsing_mode(self, parsing_mode):
        self._ParsingMode=parsing_mode

    def get_original_string(self):
        return self.InputString

    def get_next_argument(self):
        argument=''
        quoted=False

        if self._ParsingMode in (ParsingMode.CommandLineToArgvW, ParsingMode.ArgV):            
            while self.InputStringIndex<len(self.InputString):
                ch=self.InputString[self.InputStringIndex]

                if ch=='^':
                    pass

                elif self.StartsWithCommand and len(self.Arguments)==0: # First argument is special
                    if ch=='"':
                        self.QuotesCount+=1

                    if self.InputStringIndex==0:
                        if ch=='"':
                            self.QuoteStart=True
                        else:
                            argument+=ch 
                    elif self.QuoteStart==False and (ch in self.DelimiterCharacters or (self.QuotesCount>0 and self.QuotesCount%2==0)):
                        self.InputStringIndex+=1
                        break
                    elif ch in ('(', '/') or ch in self.CommandSeparator:
                        break
                    elif self.QuoteStart==True and ch=='"':
                        self.InputStringIndex+=1
                        break
                    else:
                        argument+=ch

                elif ch=='"' and (self.InputString[self.InputStringIndex-1]!='\\'):
                    if argument=='':
                        quoted=True

                    if self.InterpretState==self.InterpretState.InterpretSpecialChars:
                        self.InterpretState=State.IgnoreSpecialChars
                    elif self.InterpretState==State.IgnoreSpecialChars:
                        if self.InputStringIndex<len(self.InputString)-1 and self.InputString[self.InputStringIndex+1]=='"':
                            argument+=ch
                            self.InputStringIndex+=1

                            if self._ParsingMode==ParsingMode.CommandLineToArgvW:
                                self.InterpretState=State.InterpretSpecialChars
                        else:
                            self.InterpretState=State.InterpretSpecialChars

                elif self.InterpretState==State.InterpretSpecialChars and (ch in self.DelimiterCharacters or ch in self.CommandSeparator):
                    self.InputStringIndex+=1
                    break

                elif ord(ch)>=0x20:
                    argument+=ch

                self.InputStringIndex+=1

        elif self._ParsingMode==ParsingMode.PowerShell:
            argument=''
            self._consume_delimiters()
            if len(self.InputString)>2 and len(self.InputString)>self.InputStringIndex and self.InputString[self.InputStringIndex]=='"' and self.InputString[-1]=='"':
                single_double_quote_found=self.find_powershell_escape_strings(self.InputStringIndex+1, len(self.InputString)-1)
                   
                if not single_double_quote_found:
                    argument=self.InputString[self.InputStringIndex+1:-1]
                    self.InputStringIndex=len(self.InputString)

            if not argument:
                argument=self.InputString[self.InputStringIndex:]
                self.InputStringIndex=len(self.InputString)
                
        
        if argument or len(self.Arguments)==0:
            if len(self.Arguments)==0:
                self.ArgumentStartInputStringIndex=self.InputStringIndex

            self.Arguments.append({'String': argument, 'Quoted': quoted})

        return argument
    
    def find_powershell_escape_strings(self, start, end):
        single_double_quote_found=False
        index=start
        while index<end-1:
            if self.InputString[index]=='"':
                if self.InputString[index+1]=='"':
                    index+=1
                else:
                    single_double_quote_found=True
            index+=1
        return single_double_quote_found

    def get_argument_list(self, start_index=0, quote_arguments=True):
        arguments=self.Arguments[start_index:]
        argument_list=[]
        for argument in arguments:
            argument_list.append(argument['String'])
        return argument_list
    
    def get_arguments(self, start_index=0, quote_arguments=True):
        arguments=self.Arguments[start_index:]

        if len(arguments)==1:
            return arguments[0]['String']

        argument_line=''
        for argument in arguments:
            if argument_line:
                argument_line+=' '

            if argument['Quoted'] and quote_arguments:
                argument_line+='"'

            argument_line+=argument['String']

            if argument['Quoted'] and quote_arguments:
                argument_line+='"'
        return argument_line
    
    def has_ended(self):
        if self.InputStringIndex>=len(self.InputString):
            return True
        return False
    
    def parse_all(self):
        while self.InputStringIndex<len(self.InputString):
            self.get_next_argument()
            
    def _consume_delimiters(self):
        while self.InterpretState==State.InterpretSpecialChars and self.InputStringIndex<len(self.InputString):
            ch=self.InputString[self.InputStringIndex]

            if ch=='^' or ch in self.DelimiterCharacters or ch in self.CommandSeparator:
                self.InputStringIndex+=1
                continue
                
            break
    
    def get_remaining_string(self):
        return self.InputString[self.InputStringIndex:]
    
    def get_argument_string(self):
        return self.InputString[self.ArgumentStartInputStringIndex:]
    
    def get_current_argument_index(self):
        return len(self.Arguments)
    
    def dump_list(self, prefix=''):
        for argument in self.Arguments:
            print(prefix+'['+argument+']')


# In[1]:


import base64

class PowerShellCmdLineTransformer(Transformer):
    def __init__(self, debug=False):
        self.Debug=debug
        self.CommandLine={'String': '', 'Switches': []}

    def traverse_tree(self, item):
        if type(item) == list:
            for element in item:
                self.traverse_tree(element)
        elif type(item) == tree.Tree:
            for child in item.children:
                self.traverse_tree(child)

        elif type(item)==lexer.Token:
            if item.type.endswith('_SWITCH'):
                self.CommandLine['Switches'].append(item.value)
            elif item.type == 'COMMAND':
                self.CommandLine['String'] = item.value
            elif item.type == 'ENCODED_COMMAND':
                self.CommandLine['EncodedString'] = item.value
                
                try:
                    self.CommandLine['String'] = base64.b64decode(item.value).decode("utf-16")
                except:
                    traceback.print_exc()
                    print('='*80)
                    print("* Failed to decode command:")
                    print(item.value)
                    print('')
                    
    def value(self, args):
        self.traverse_tree(args)
        return self.CommandLine

class PowerShellCmdLineParser:
    CmdExeGrammar = r"""
        value: cmdline
        cmdline: switch (SPACE switch)* SPACE*
        switch: NO_VALUE_SWITCHES | WINDOW_STYLE_SWITCH | NO_PROFILE_SWITCH | NO_LOGO_SWITCH | NO_EXIT_SWITCH | NO_SWITCH | EXECUTION_POLICY_SWITCH | command_switch | encoded_command_switch | COMMAND

        WINDOW_STYLE_SWITCH: /(-W|-Wi|-Wind|-Windo|-Window|-WindowS|-WindowSt|-WindowSty|-WindowStyl|-WindowStyle)[ \t]+[a-zA-Z0-9]+/i
        NO_PROFILE_SWITCH: "-NoProfile"i | "-nop"i
        NO_LOGO_SWITCH: "-NoLogo"i
        NO_EXIT_SWITCH: "-NoExit"i
        NO_SWITCH: /-No[A-Za-z]+/i
        NO_VALUE_SWITCHES: /(-sta|-noni|-mta|-noninteractive)/i
        WITH_VALUE_SWITCH: /(-inputformat|-outputformat|-psconsolefile|-version|-file)[ \t]+[a-zA-Z0-9]+/i
        EXECUTION_POLICY_SWITCH: /(-ex|-exe|-exec|-execu|-execut|-executi|-executio|-execution|-executionp|-executionpo|-executionpol|-executionpoli|-executionpolic|-executionpolicy|-ep)[ \t]+[a-zA-Z]+/i

        command_switch: /(-command|-c)[ \t]+/i COMMAND
        encoded_command_switch: /(-e|-ec|-enc|-enco|-encod|-encode|-encoded|-encodedc|-encodedc|-encodedco|-encodedcom|-encodedcomm|-encodedcomma|-encodedcomman|-encodedcommand)[ \t]+/i ENCODED_COMMAND
        
        COMMAND: /.+/i
        ENCODED_COMMAND: /.+/i

        SPACE: /[ \t\r\n]+/

        %import common.ESCAPED_STRING
    """
   
    def __init__(self, string, arg_start_index=0, debug=False):
        if type(string)==str:
            self.CommandLineIterator=CommandLineItertor(string, parsing_mode = ParsingMode.PowerShell)
        else:
            self.CommandLineIterator=string
            self.CommandLineIterator.set_parsing_mode(ParsingMode.PowerShell)
        self.Debug=debug
        self.ArgStartIndex=arg_start_index

    def parse(self):
        if self.Debug:
            print('PowerShellCmdLineParser.Parse >>')
            
        self.CommandLineIterator.parse_all()
        argument_string=self.CommandLineIterator.get_arguments(start_index=self.ArgStartIndex, quote_arguments=False)

        if self.Debug:
            print('argument_string: ' + argument_string)
    
        return {
            'PowerShellString': argument_string,
            'ParseResult': self.parse_string(argument_string)
        }
        
    def parse_string(self, command_line):
        parsed_result = None
        parser = Lark(self.CmdExeGrammar, parser='lalr', start='value', debug=True) 
        
        try:
            if command_line:              
                parsed_result = parser.parse(command_line)
            
            if parsed_result:
                return PowerShellCmdLineTransformer(debug=self.Debug).transform(parsed_result)
        except:
            traceback.print_exc()

        return parsed_result


# In[7]:


class CmdExeTransformer(Transformer):
    def __init__(self, debug=False):
        self.Debug=debug
        self.CommandLines=[]

    def traverse_tree(self, item):
        if type(item) == list:
            for element in item:
                self.traverse_tree(element)

        elif type(item) == tree.Tree:
            if item.data == 'cmdline':
                self.CommandLines.append({'CommandLine': '', 'Switches': []})
            for child in item.children:
                self.traverse_tree(child)

        elif type(item)==lexer.Token:
            if item.type == 'SWITCH':
                self.CommandLines[-1]['Switches'].append(item.value)
            elif item.type in ('COMMAND', 'ESCAPED_COMMAND'):
                self.CommandLines[-1]['CommandLine'] = {'String': item.value}
                command_line_parser=CommandLineParser(item.value)
                command_line_parse_result=command_line_parser.parse()
                self.CommandLines[-1]['CommandLine']['ParseResult']=command_line_parse_result

            elif item.type == 'AMPERSAND':
                self.CommandLines.append({'CommandLine': '', 'Switches': []})

    def value(self, args):
        self.traverse_tree(args)
        return self.CommandLines

class CmdExeParser:
    CmdExeGrammar = r"""
        value: cmdline
        cmdline: SPACE* AMPERSAND* (SPACE SWITCH | SWITCH)* (SPACE command | command)*
        SWITCH: /\/[a-zA-Z\?]/
        command: (ESCAPED_COMMAND | COMMAND) AMPERSAND*
        ESCAPED_COMMAND: ESCAPED_STRING
        COMMAND: /[^\/ &][^&]*/
        AMPERSAND: "&"
        SPACE: /[ \t\r\n]+/
        %import common.ESCAPED_STRING
    """
   
    def __init__(self, command_line_itertor = None, start_arg=1, debug=False):
        self.CommandLineIterator=command_line_itertor
        self.StartArg=start_arg
        self.Debug=debug

    def parse(self):
        if self.Debug:
            print('CmdExeParser.Parse >>')
            
        self.CommandLineIterator.parse_all()
        normalized_cmd_line=self.CommandLineIterator.get_arguments(self.StartArg)
        
        if self.Debug:
            print("Normalized Command Line: [" + normalized_cmd_line + "]")

        parsed_result=self.parse_string(normalized_cmd_line)

        return {
            'String': normalized_cmd_line,
            'ParseResult': parsed_result
        }

    def parse_string(self,command_line):
        parsed_result = None
        parser = Lark(self.CmdExeGrammar, parser='lalr', start='value')

        try:
            if command_line:              
                parsed_result = parser.parse(command_line)
            
            if parsed_result:
                return CmdExeTransformer(debug=self.Debug).transform(parsed_result)
        except:
            traceback.print_exc()

        return parsed_result


# In[3]:


import json
import pprint 

class CommandLineParser:
    def __init__(self, string = None, debug=False, parsers=("cmd", "powershell")):
        if type(string)==str:
            self.CommandLineIterator=CommandLineItertor(string)
        else:
            self.CommandLineIterator=string        
        self.Debug=debug
        self.Parsers=parsers

    def parse(self):
        command=self.CommandLineIterator.get_next_argument()

        if "cmd" in self.Parsers and command.lower() in ('cmd', 'cmd.exe'):
            argument_parsed_result=CmdExeParser(self.CommandLineIterator, debug=self.Debug).parse()
        elif "powershell" in self.Parsers and command.lower() in ('powershell', 'powershell.exe'):
            argument_parsed_result=PowerShellCmdLineParser(self.CommandLineIterator, arg_start_index=1, debug=self.Debug).parse()         
        else:
            current_argument_index=self.CommandLineIterator.get_current_argument_index()
            self.CommandLineIterator.parse_all()

            argument_list=[]
            for argument_str in self.CommandLineIterator.get_argument_list(current_argument_index+1):
                argument={'String': argument_str}
                try:
                    decoded_argument=base64.b64decode(argument_str).decode("utf-16")
                    argument['DecodedString']=decoded_argument
                except:
                    pass
                argument_list.append(argument)

            argument_parsed_result=argument_list

        return {
            'CommandLine': {
                'String': self.CommandLineIterator.get_original_string(),
                'ParseResult': {
                    'Command': command,
                    'Argument': argument_parsed_result
                }
            }    
        }

