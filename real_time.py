import pandas as pd
import requests as res
import re
from urllib.parse import urlparse
import numpy as np
import json as js
import time as tm 
import ipaddress as ips

class TrainData:
    def __init__(self,target=[],file1=[],file2=[],log=[],vapi='',tapi=''):
        self.target = target
        self.file1 = file1
        self.file2 = file2
        self.log = log
        self.vapi = "virus total api token"
        self.tapi = "Telegram api token"
       
    def read_file(self,file1):
        with open(file1, "r")  as file:
            filelist = file.read().splitlines() 
            return sorted(set(filelist))
        
    
           
    def read_log(self,log):
      
        with open(log,"r") as logs:
            logs.seek(0,2)
            while True:
                line=logs.readline()

                if line:
                    try:
                        tar = line.split()
                        self.log=[]
                        self.log.append(tar[6]) 
                        self.log.append(tar[2]) 
                        return self.log
                    except IndexError:
                          self.log=['google.com','20.22.223.21']

    def target_checking(self):
        value = self.read_log('/var/log/squid/access.log')
        files = self.read_file('/hdd/ai_project/project_b/check_list')
        domain =''
        if not value[0].startswith(('http://','https://')):
                    domain = 'https://'+value[0]
                    parsed_url = urlparse(domain)
                    domain = parsed_url.netloc.split(':')[0] 
        left, right = 0, len(files) -1 
        while left <= right:
            mid = left + (right - left) // 2
            try:
                if files[mid] == domain:
                    return 1
            
                elif files[mid] < domain:
                    left = mid + 1

                elif files[mid] > domain:
                    right = mid - 1 
            except IndexError:
                    pass
        return value
        
    # def analysis(self):
    #     #threat detector 
    #     while True:
    #         result = self.target_checking()
    #         if result == 1:
    #             result = 1
    #         return result
    
    def binary_search(self,files,value):
        files.sort()
        left, right = 0, len(files) -1 
        while left <= right:
            mid = left + (right - left) // 2
           
            if files[mid] == value:
                return 1
            
            elif value[0] is None:
                return 1
            
            elif files[mid] < value:
                left = mid + 1

            elif files[mid] > value:
                right = mid - 1 

        return f'{value} {files}'
    
    def threat_checker(self):
        try:
         while True:
            data = self.target_checking()
            if data == 1:
                return "duplicate data"
            headers = {
    "accept": "application/json",
    "x-apikey": self.vapi

    }       
            domain = ''
            try:
                if ips.ip_address(data[0]):
                    return data[0]
               
            except ValueError:
            
                if not data[0].startswith(('http://','https://')):
                    domain = 'https://'+data[0]
                parsed_url = urlparse(domain)
                domain = parsed_url.netloc.split(':')[0] 

                test = f'https://www.virustotal.com/api/v3/domains/{domain}'
                response = res.get(test, headers=headers).json()
                malicious = response['data']['attributes']['last_analysis_stats']['malicious']
                suspicious = response['data']['attributes']['last_analysis_stats']['suspicious']
            #converts data to machine learning 
                url = f"https://api.telegram.org/bot{self.tapi}/sendMessage"
            

                if malicious > 0 or suspicious > 0:
                    params = {
                'chat_id': '-4753820501',
                'text': f'User IP: {data[1]}\n Malicious site:{response['data']['id']}\n Mal Rate:  {malicious}/100\n Susp Rate: {suspicious}/100 \n (Note: need to check device'
    }
                    responses = res.post(url, params=params)
                    vals= response['data']['id']
                    bt = self.block(vals)
                    ch = self.checklist(vals)
                    if malicious > 0:
                        ml = self.change_ML_data(response['data']['id'],1,0)
                    if suspicious > 0:
                        ml = self.change_ML_data(response['data']['id'],0,1)
                    if malicious > 0 and suspicious > 0:
                        ml = self.change_ML_data(response['data']['id'],1,1)
                    return f'{bt}{ml}{ch}'
                else:
                    vals= response['data']['id']
                    ch = self.checklist(vals)
                    ml = self.change_ML_data(response['data']['id'],0,0)
                    return f'{ml}'
                
        except KeyError:
           pass
                                     

    #block-work

    def checklist(self,value):
        #general checklist
        with open('/hdd/ai_project/project_b/check_list','r+') as op:
            lines = op.read().splitlines()
            data = self.binary_search(lines,value)
            if data == 1:
                return f"Duplicate {data}"
                
            else:
                op.write(f"\n{value}")
                op.close()
    def block(self,value):

        with open('/etc/squid/block.txt','r+') as ops:
            lines2 = ops.read().splitlines()
            data2 = self.binary_search(lines2,value)
            if data2 == 1:
                return f"Duplicate{data2}"
                
            else:
                ops.write(f"\n{value}")
                ops.close()
                return "File wirte"
            

           
    def change_ML_data(self,domain,mal,sus):
        with open("/hdd/ai_project/project_b/history.json","r+") as hs:
            data = js.load(hs)
            dar = self.binary_search(data['domain'],domain)
            if dar == 1:
                return f"Darplicat {dar}"
            else:
                
                data['domain'].insert(0,domain)
                data['malicious'].insert(0,mal)
                data['suspicious'].insert(0,sus)
                hs.seek(0)
                js.dump(data,hs,indent=4)
                               
ai = TrainData()

while True:
    print(ai.threat_checker())
    
     
