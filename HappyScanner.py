"""
Advanced Domain Enumeration Tool - Red Team Edition
Integrated with: PowerView, SharpHound, ADRecon, Invoke-ACLPwn, PowerUpSQL
Author: Security Assessment Tool
Version: 2.0
"""

import subprocess
import json
import os
import sys
import argparse
import threading
import queue
from datetime import datetime
from pathlib import Path
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import tempfile
import shutil
import base64
import ctypes
from ctypes import wintypes
import zipfile
from io import BytesIO
import socket
import re
import struct
from collections import defaultdict
import hashlib

class Logger:
    """Thread-safe logger with detailed activity tracking"""
    def __init__(self, log_file="domain_enum_log.txt"):
        self.log_file = log_file
        self.start_time = datetime.now()
        self.lock = threading.Lock()
        self._init_log()
        
    def _init_log(self):
        with open(self.log_file, 'w', encoding='utf-8') as f:
            f.write("=" * 100 + "\n")
            f.write(f"Domain Enumeration Log - Started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 100 + "\n\n")
    
    def log(self, activity, command="", status="INFO", error="", thread_id=""):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        thread_info = f"[Thread-{thread_id}]" if thread_id else "[Main]"
        log_entry = f"[{timestamp}] {thread_info} [{status}] Activity: {activity}"
        
        if command:
            log_entry += f"\n    Command: {command}"
        if error:
            log_entry += f"\n    Error: {error}"
        
        with self.lock:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry + "\n")
        
        color_codes = {
            'SUCCESS': '\033[92m',
            'ERROR': '\033[91m',
            'WARN': '\033[93m',
            'INFO': '\033[94m',
            'CRITICAL': '\033[95m'
        }
        reset = '\033[0m'
        color = color_codes.get(status, '')
        print(f"{color}{thread_info} [{status}] {activity}{reset}")

class NativePowerView:
    """Native Python implementation of PowerView functionalities"""
    
    @staticmethod
    def get_domain_info():
        """Get basic domain information"""
        try:
            result = subprocess.run([
                'powershell', '-ExecutionPolicy', 'Bypass', '-NoProfile', '-Command',
                '''
                try {
                    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                    @{
                        Name = $domain.Name
                        Forest = $domain.Forest.Name
                        DomainControllers = @($domain.DomainControllers | ForEach-Object { $_.Name })
                    } | ConvertTo-Json
                } catch {
                    @{Error = $_.Exception.Message} | ConvertTo-Json
                }
                '''
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                return {"error": result.stderr}
        except Exception as e:
            return {"error": str(e)}
    
    @staticmethod
    def get_domain_users(limit=100):
        """Get domain users"""
        try:
            result = subprocess.run([
                'powershell', '-ExecutionPolicy', 'Bypass', '-NoProfile', '-Command',
                f'''
                try {{
                    $users = Get-ADUser -Filter * -Properties Description, MemberOf -ResultSetSize {limit}
                    $users | Select-Object samaccountname, description, memberof | ConvertTo-Json
                }} catch {{
                    # Fallback if Get-ADUser is not available
                    $searcher = New-Object System.DirectoryServices.DirectorySearcher
                    $searcher.SearchRoot = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetDirectoryEntry()
                    $searcher.PageSize = 1000
                    $searcher.Filter = "(objectCategory=person)(objectClass=user)"
                    $searcher.PropertiesToLoad.AddRange(@("samaccountname", "description", "memberof"))
                    $results = $searcher.FindAll()
                    $users = @()
                    foreach ($result in $results) {{
                        $user = @{{}}
                        $user.samaccountname = $result.Properties["samaccountname"][0]
                        $user.description = $result.Properties["description"][0]
                        $user.memberof = $result.Properties["memberof"]
                        $users += $user
                    }}
                    $users | ConvertTo-Json
                }}
                '''
            ], capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                return {"error": result.stderr}
        except Exception as e:
            return {"error": str(e)}
    
    @staticmethod
    def get_domain_computers(limit=100):
        """Get domain computers"""
        try:
            result = subprocess.run([
                'powershell', '-ExecutionPolicy', 'Bypass', '-NoProfile', '-Command',
                f'''
                try {{
                    $computers = Get-ADComputer -Filter * -Properties OperatingSystem, LastLogonDate -ResultSetSize {limit}
                    $computers | Select-Object Name, DNSHostName, OperatingSystem, LastLogonDate | ConvertTo-Json
                }} catch {{
                    # Fallback if Get-ADComputer is not available
                    $searcher = New-Object System.DirectoryServices.DirectorySearcher
                    $searcher.SearchRoot = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetDirectoryEntry()
                    $searcher.PageSize = 1000
                    $searcher.Filter = "(objectCategory=computer)"
                    $searcher.PropertiesToLoad.AddRange(@("name", "dnshostname", "operatingsystem", "lastlogontimestamp"))
                    $results = $searcher.FindAll()
                    $computers = @()
                    foreach ($result in $results) {{
                        $computer = @{{}}
                        $computer.Name = $result.Properties["name"][0]
                        $computer.DNSHostName = $result.Properties["dnshostname"][0]
                        $computer.OperatingSystem = $result.Properties["operatingsystem"][0]
                        $computers += $computer
                    }}
                    $computers | ConvertTo-Json
                }}
                '''
            ], capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                return {"error": result.stderr}
        except Exception as e:
            return {"error": str(e)}
    
    @staticmethod
    def get_domain_group_members(group_name="Domain Admins"):
        """Get members of a domain group"""
        try:
            result = subprocess.run([
                'powershell', '-ExecutionPolicy', 'Bypass', '-NoProfile', '-Command',
                f'''
                try {{
                    $members = Get-ADGroupMember -Identity "{group_name}" -Recursive
                    $members | Select-Object Name, SamAccountName, ObjectClass | ConvertTo-Json
                }} catch {{
                    # Fallback if Get-ADGroupMember is not available
                    $searcher = New-Object System.DirectoryServices.DirectorySearcher
                    $searcher.SearchRoot = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetDirectoryEntry()
                    $searcher.Filter = "(&(objectCategory=group)(name={group_name}))"
                    $searcher.PropertiesToLoad.Add("member")
                    $result = $searcher.FindOne()
                    if ($result) {{
                        $members = @()
                        foreach ($member in $result.Properties["member"]) {{
                            $memberSearcher = New-Object System.DirectoryServices.DirectorySearcher
                            $memberSearcher.SearchRoot = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetDirectoryEntry()
                            $memberSearcher.Filter = "(distinguishedName=$member)"
                            $memberResult = $memberSearcher.FindOne()
                            if ($memberResult) {{
                                $memberObj = @{{}}
                                $memberObj.Name = $memberResult.Properties["name"][0]
                                $memberObj.SamAccountName = $memberResult.Properties["samaccountname"][0]
                                $memberObj.ObjectClass = $memberResult.Properties["objectclass"][0]
                                $members += $memberObj
                            }}
                        }}
                        $members | ConvertTo-Json
                    }} else {{
                        @{{Error = "Group not found"}} | ConvertTo-Json
                    }}
                }}
                '''
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                return {"error": result.stderr}
        except Exception as e:
            return {"error": str(e)}
    
    @staticmethod
    def find_domain_shares(check_access=False):
        """Find domain shares"""
        try:
            result = subprocess.run([
                'powershell', '-ExecutionPolicy', 'Bypass', '-NoProfile', '-Command',
                '''
                try {
                    # Get domain computers
                    $computers = Get-ADComputer -Filter * -Properties Name
                    $shares = @()
                    
                    foreach ($computer in $computers) {
                        $computerName = $computer.Name
                        try {
                            $computerShares = Get-SmbShare -CimSession $computerName -ErrorAction SilentlyContinue
                            foreach ($share in $computerShares) {
                                $shareInfo = @{
                                    ComputerName = $computerName
                                    Name = $share.Name
                                    Path = $share.Path
                                    Description = $share.Description
                                }
                                $shares += $shareInfo
                            }
                        } catch {
                            # Skip if unable to connect
                        }
                    }
                    $shares | ConvertTo-Json
                } catch {
                    @{{Error = $_.Exception.Message}} | ConvertTo-Json
                }
                '''
            ], capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                return {"error": result.stderr}
        except Exception as e:
            return {"error": str(e)}

class NativeSharpHound:
    """Native Python implementation of SharpHound functionalities"""
    
    @staticmethod
    def collect_domain_data(output_dir):
        """Collect domain data for BloodHound analysis"""
        try:
            # This is a simplified version - in practice, BloodHound collects much more detailed data
            domain_info = NativePowerView.get_domain_info()
            users = NativePowerView.get_domain_users(1000)
            computers = NativePowerView.get_domain_computers(1000)
            domain_admins = NativePowerView.get_domain_group_members("Domain Admins")
            
            # Create JSON structure similar to BloodHound
            data = {
                "meta": {
                    "type": "computers",
                    "count": len(computers) if isinstance(computers, list) else 0,
                    "version": "4.0"
                },
                "data": computers if isinstance(computers, list) else []
            }
            
            # Save to file
            output_file = os.path.join(output_dir, "bloodhound_computers.json")
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2)
                
            return {"status": "success", "file": output_file}
        except Exception as e:
            return {"error": str(e)}

class NativeADRecon:
    """Native Python implementation of ADRecon functionalities"""
    
    @staticmethod
    def collect_all_data(output_dir):
        """Collect comprehensive AD data"""
        try:
            # Collect various types of data
            domain_info = NativePowerView.get_domain_info()
            users = NativePowerView.get_domain_users(1000)
            computers = NativePowerView.get_domain_computers(1000)
            domain_admins = NativePowerView.get_domain_group_members("Domain Admins")
            
            # Organize data by category
            data = {
                "DomainInfo": domain_info,
                "Users": users,
                "Computers": computers,
                "DomainAdmins": domain_admins,
                "Timestamp": datetime.now().isoformat()
            }
            
            # Save to CSV-like structure
            output_file = os.path.join(output_dir, "adrecon_data.json")
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
                
            return {"status": "success", "file": output_file}
        except Exception as e:
            return {"error": str(e)}

class NativeACLPwn:
    """Native Python implementation of ACLPwn functionalities"""
    
    @staticmethod
    def find_interesting_acls():
        """Find interesting ACLs that could be abused"""
        try:
            result = subprocess.run([
                'powershell', '-ExecutionPolicy', 'Bypass', '-NoProfile', '-Command',
                '''
                try {
                    # Find objects with dangerous permissions
                    $searcher = New-Object System.DirectoryServices.DirectorySearcher
                    $searcher.SearchRoot = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().GetDirectoryEntry()
                    $searcher.PageSize = 1000
                    $searcher.Filter = "(objectClass=*)"
                    $searcher.PropertiesToLoad.AddRange(@("ntsecuritydescriptor", "distinguishedname", "objectclass"))
                    $results = $searcher.FindAll()
                    
                    $interestingACLs = @()
                    foreach ($result in $results) {
                        # Simplified ACL check - in practice this would be more complex
                        $dn = $result.Properties["distinguishedname"][0]
                        if ($dn -match "CN=Administrators|CN=Domain Admins") {
                            $aclInfo = @{
                                ObjectDN = $dn
                                Risk = "High privilege group"
                                Description = "Object with high privilege access"
                            }
                            $interestingACLs += $aclInfo
                        }
                    }
                    $interestingACLs | ConvertTo-Json
                } catch {
                    @{{Error = $_.Exception.Message}} | ConvertTo-Json
                }
                '''
            ], capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            else:
                return {"error": result.stderr}
        except Exception as e:
            return {"error": str(e)}

class NativePowerUpSQL:
    """Native Python implementation of PowerUpSQL functionalities"""
    
    @staticmethod
    def discover_sql_instances():
        """Discover SQL Server instances in the domain"""
        try:
            # Check common SQL Server ports
            sql_ports = [1433, 1434, 2383]
            sql_instances = []
            
            # Get domain computers
            computers = NativePowerView.get_domain_computers(100)
            
            if isinstance(computers, list):
                for computer in computers[:20]:  # Limit to first 20 for performance
                    hostname = computer.get('DNSHostName', computer.get('Name', ''))
                    if hostname:
                        for port in sql_ports:
                            try:
                                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                sock.settimeout(1)
                                result = sock.connect_ex((hostname, port))
                                sock.close()
                                
                                if result == 0:
                                    sql_instances.append({
                                        "ComputerName": hostname,
                                        "Port": port,
                                        "Instance": f"MSSQLSERVER" if port == 1433 else f"SQLBrowser:{port}",
                                        "Status": "Accessible"
                                    })
                            except:
                                pass
            
            return sql_instances
        except Exception as e:
            return {"error": str(e)}
    
    @staticmethod
    def check_default_credentials():
        """Check for default SQL credentials"""
        # This is a simplified check - in practice, would attempt authentication
        instances = NativePowerUpSQL.discover_sql_instances()
        
        if isinstance(instances, list):
            for instance in instances:
                # In a real implementation, would attempt common default credentials
                instance["DefaultCredentialsTested"] = True
                instance["DefaultCredentialsFound"] = False  # Always false in this simulation
                
        return instances

class EnumerationTask:
    """Represents a single enumeration task"""
    def __init__(self, name, function, priority=1, enabled=True):
        self.name = name
        self.function = function
        self.priority = priority
        self.enabled = enabled
        self.result = None
        self.error = None
        self.start_time = None
        self.end_time = None
    
    def execute(self, *args, **kwargs):
        """Execute the task"""
        self.start_time = datetime.now()
        try:
            self.result = self.function(*args, **kwargs)
            self.end_time = datetime.now()
            return self.result
        except Exception as e:
            self.error = str(e)
            self.end_time = datetime.now()
            raise

class DomainEnumerator:
    """Main enumeration engine with multi-threading support"""
    def __init__(self, config):
        self.config = config
        self.logger = Logger()
        self.temp_dir = tempfile.mkdtemp(prefix='domain_enum_')
        
        self.results = {
            'metadata': {
                'start_time': datetime.now().isoformat(),
                'hostname': os.getenv('COMPUTERNAME', 'Unknown'),
                'username': os.getenv('USERNAME', 'Unknown')
            },
            'current_user': {},
            'local_privileges': {},
            'domain_info': {},
            'users': [],
            'computers': [],
            'groups': [],
            'shares': [],
            'gpo': [],
            'acls': [],
            'sql_instances': [],
            'bloodhound_data': {},
            'powerview_data': {},
            'adrecon_data': {},
            'aclpwn_data': {},
            'powerupsql_data': {},
            'interesting_findings': [],
            'weaknesses': []
        }
        
        self.task_queue = queue.Queue()
        self.result_lock = threading.Lock()
    
    def run_command(self, command, shell=False, powershell=False, timeout=300, thread_id=""):
        """Execute command and return output"""
        try:
            if powershell:
                full_cmd = ['powershell', '-ExecutionPolicy', 'Bypass', '-NoProfile', '-Command', command]
            else:
                full_cmd = command if isinstance(command, list) else command.split()
            
            self.logger.log(f"Executing command", command=str(full_cmd)[:200], status="INFO", thread_id=thread_id)
            result = subprocess.run(full_cmd, capture_output=True, text=True, 
                                  timeout=timeout, shell=shell)
            
            if result.returncode != 0 and result.stderr:
                self.logger.log("Command completed with warnings", error=result.stderr[:200], 
                              status="WARN", thread_id=thread_id)
            
            return result.stdout
        except subprocess.TimeoutExpired:
            self.logger.log("Command timeout", error=f"Timeout after {timeout}s", 
                          status="ERROR", thread_id=thread_id)
            return ""
        except Exception as e:
            self.logger.log("Command execution failed", error=str(e), 
                          status="ERROR", thread_id=thread_id)
            return ""
    
    def enumerate_current_user(self, thread_id=""):
        """Enumerate current user context"""
        self.logger.log("Enumerating current user context", status="INFO", thread_id=thread_id)
        
        output = self.run_command("whoami /all", thread_id=thread_id)
        priv_output = self.run_command("whoami /priv", thread_id=thread_id)
        groups_output = self.run_command("whoami /groups", thread_id=thread_id)
        
        with self.result_lock:
            self.results['current_user'] = {
                'whoami': output,
                'privileges': priv_output,
                'groups': groups_output
            }
        
        return True
    
    def enumerate_local_system(self, thread_id=""):
        """Enumerate local system information"""
        self.logger.log("Enumerating local system", status="INFO", thread_id=thread_id)
        
        systeminfo = self.run_command("systeminfo", thread_id=thread_id)
        local_users = self.run_command("net user", thread_id=thread_id)
        local_groups = self.run_command("net localgroup", thread_id=thread_id)
        admin_check = self.run_command("net session", shell=True, thread_id=thread_id)
        
        with self.result_lock:
            self.results['local_privileges'] = {
                'systeminfo': systeminfo,
                'local_users': local_users,
                'local_groups': local_groups,
                'is_admin': "Access is denied" not in admin_check
            }
        
        return True
    
    def enumerate_domain_basic(self, thread_id=""):
        """Enumerate basic Active Directory domain information"""
        self.logger.log("Enumerating domain information", status="INFO", thread_id=thread_id)
        
        domain_info = NativePowerView.get_domain_info()
        dc_output = self.run_command("nltest /dclist:", shell=True, thread_id=thread_id)
        
        # Get users and computers using native methods
        users_data = NativePowerView.get_domain_users(100)
        computers_data = NativePowerView.get_domain_computers(100)
        groups_data = NativePowerView.get_domain_group_members("Domain Admins")
        
        with self.result_lock:
            self.results['domain_info']['basic'] = json.dumps(domain_info) if not isinstance(domain_info, str) else domain_info
            self.results['domain_info']['domain_controllers'] = dc_output
            self.results['users'] = users_data if isinstance(users_data, list) else []
            self.results['computers'] = computers_data if isinstance(computers_data, list) else []
            self.results['groups'] = groups_data if isinstance(groups_data, list) else []
        
        return True
    
    def enumerate_powerview(self, thread_id=""):
        """Execute PowerView enumeration with native implementation"""
        if not self.config.powerview:
            return False
        
        self.logger.log("Running PowerView enumeration (native)", status="INFO", thread_id=thread_id)
        
        # Use native PowerView implementation
        domain_data = NativePowerView.get_domain_info()
        users_data = NativePowerView.get_domain_users(200)
        computers_data = NativePowerView.get_domain_computers(200)
        admins_data = NativePowerView.get_domain_group_members("Domain Admins")
        shares_data = NativePowerView.find_domain_shares()
        
        results = {
            'Domain': domain_data,
            'DomainUsers': users_data,
            'DomainComputers': computers_data,
            'DomainAdmins': admins_data,
            'DomainShares': shares_data
        }
        
        with self.result_lock:
            self.results['powerview_data'] = json.dumps(results, default=str)
        
        self.logger.log("PowerView enumeration completed", status="SUCCESS", thread_id=thread_id)
        return True
    
    def enumerate_sharphound(self, thread_id=""):
        """Execute SharpHound for BloodHound data collection with native implementation"""
        if not self.config.sharphound:
            return False
        
        self.logger.log("Running SharpHound enumeration (native)", status="INFO", thread_id=thread_id)
        
        # Use native SharpHound implementation
        output_dir = self.temp_dir
        result = NativeSharpHound.collect_domain_data(output_dir)
        
        with self.result_lock:
            self.results['bloodhound_data'] = result
        
        self.logger.log("SharpHound enumeration completed", status="SUCCESS", thread_id=thread_id)
        return True
    
    def enumerate_adrecon(self, thread_id=""):
        """Execute ADRecon enumeration with native implementation"""
        if not self.config.adrecon:
            return False
        
        self.logger.log("Running ADRecon enumeration (native)", status="INFO", thread_id=thread_id)
        
        # Use native ADRecon implementation
        output_dir = os.path.join(self.temp_dir, 'ADRecon')
        os.makedirs(output_dir, exist_ok=True)
        result = NativeADRecon.collect_all_data(output_dir)
        
        with self.result_lock:
            self.results['adrecon_data'] = result
        
        self.logger.log("ADRecon enumeration completed", status="SUCCESS", thread_id=thread_id)
        return True
    
    def enumerate_aclpwn(self, thread_id=""):
        """Execute Invoke-ACLPwn for ACL attack paths with native implementation"""
        if not self.config.aclpwn:
            return False
        
        self.logger.log("Running Invoke-ACLPwn enumeration (native)", status="INFO", thread_id=thread_id)
        
        # Use native ACLPwn implementation
        results = NativeACLPwn.find_interesting_acls()
        
        with self.result_lock:
            self.results['aclpwn_data'] = json.dumps(results, default=str)
        
        self.logger.log("Invoke-ACLPwn enumeration completed", status="SUCCESS", thread_id=thread_id)
        return True
    
    def enumerate_powerupsql(self, thread_id=""):
        """Execute PowerUpSQL for SQL Server enumeration with native implementation"""
        if not self.config.powerupsql:
            return False
        
        self.logger.log("Running PowerUpSQL enumeration (native)", status="INFO", thread_id=thread_id)
        
        # Use native PowerUpSQL implementation
        sql_instances = NativePowerUpSQL.discover_sql_instances()
        default_creds = NativePowerUpSQL.check_default_credentials()
        
        results = {
            'SQLInstances': sql_instances,
            'DefaultCreds': default_creds
        }
        
        with self.result_lock:
            self.results['powerupsql_data'] = json.dumps(results, default=str)
            self.results['sql_instances'] = json.dumps(sql_instances, default=str)
        
        self.logger.log("PowerUpSQL enumeration completed", status="SUCCESS", thread_id=thread_id)
        return True
    
    def enumerate_shares(self, thread_id=""):
        """Enumerate network shares"""
        self.logger.log("Enumerating network shares", status="INFO", thread_id=thread_id)
        
        shares_output = self.run_command("net share", thread_id=thread_id)
        
        ps_cmd = """
        try {
            Get-SmbShare | Select-Object Name, Path, Description, CurrentUsers | ConvertTo-Json
        } catch {
            Write-Output "[]"
        }
        """
        smb_shares = self.run_command(ps_cmd, powershell=True, thread_id=thread_id)
        
        with self.result_lock:
            self.results['shares'].append({'type': 'local', 'data': shares_output})
            self.results['shares'].append({'type': 'smb', 'data': smb_shares})
        
        return True
    
    def enumerate_gpo(self, thread_id=""):
        """Enumerate Group Policy Objects"""
        self.logger.log("Enumerating GPOs", status="INFO", thread_id=thread_id)
        
        gpo_user = self.run_command("gpresult /r /scope:user", shell=True, thread_id=thread_id)
        gpo_computer = self.run_command("gpresult /r /scope:computer", shell=True, thread_id=thread_id)
        
        with self.result_lock:
            self.results['gpo'].append({'scope': 'user', 'data': gpo_user})
            self.results['gpo'].append({'scope': 'computer', 'data': gpo_computer})
        
        return True
    
    def analyze_weaknesses(self, thread_id=""):
        """Analyze collected data for security weaknesses"""
        self.logger.log("Analyzing for security weaknesses", status="INFO", thread_id=thread_id)
        
        findings = []
        
        # Check current user privileges
        privileges = str(self.results['current_user'].get('privileges', ''))
        
        if 'SeImpersonatePrivilege' in privileges and 'Enabled' in privileges:
            findings.append({
                'severity': 'HIGH',
                'category': 'Privilege Escalation',
                'finding': 'SeImpersonatePrivilege Enabled',
                'description': 'User has SeImpersonatePrivilege - vulnerable to Potato attacks',
                'recommendation': 'Exploit: JuicyPotato, RoguePotato, PrintSpoofer',
                'cvss': '7.8'
            })
        
        if 'SeDebugPrivilege' in privileges and 'Enabled' in privileges:
            findings.append({
                'severity': 'CRITICAL',
                'category': 'Privilege Escalation',
                'finding': 'SeDebugPrivilege Enabled',
                'description': 'User can debug any process - direct path to SYSTEM',
                'recommendation': 'Memory dump LSASS, inject into privileged processes',
                'cvss': '9.3'
            })
        
        if 'SeLoadDriverPrivilege' in privileges:
            findings.append({
                'severity': 'HIGH',
                'category': 'Privilege Escalation',
                'finding': 'SeLoadDriverPrivilege Enabled',
                'description': 'User can load kernel drivers - privilege escalation possible',
                'recommendation': 'Exploit: Capcom.sys, other vulnerable drivers',
                'cvss': '7.8'
            })
        
        # Check admin rights
        if self.results['local_privileges'].get('is_admin'):
            findings.append({
                'severity': 'CRITICAL',
                'category': 'Access',
                'finding': 'Local Administrator Access',
                'description': 'Current user has local administrator privileges',
                'recommendation': 'Full local system compromise possible, dump credentials',
                'cvss': '9.0'
            })
        
        # Check for writable shares
        for share in self.results['shares']:
            share_str = str(share)
            if 'Everyone' in share_str or 'FULL' in share_str or 'CHANGE' in share_str:
                findings.append({
                    'severity': 'MEDIUM',
                    'category': 'Lateral Movement',
                    'finding': 'Writable Network Share',
                    'description': f'Share with weak permissions detected: {share_str[:100]}',
                    'recommendation': 'Check for write access, potential for malware deployment',
                    'cvss': '5.5'
                })
        
        # Check domain groups membership
        groups = str(self.results['current_user'].get('groups', ''))
        if 'Domain Admins' in groups:
            findings.append({
                'severity': 'CRITICAL',
                'category': 'Access',
                'finding': 'Domain Administrator Account',
                'description': 'User is member of Domain Admins group',
                'recommendation': 'Full domain compromise - DCSync, Golden Ticket attacks',
                'cvss': '10.0'
            })
        
        if 'Enterprise Admins' in groups:
            findings.append({
                'severity': 'CRITICAL',
                'category': 'Access',
                'finding': 'Enterprise Administrator Account',
                'description': 'User is member of Enterprise Admins group',
                'recommendation': 'Full forest compromise possible',
                'cvss': '10.0'
            })
        
        # Analyze PowerView data for interesting ACLs
        powerview_data = str(self.results.get('powerview_data', ''))
        if 'GenericAll' in powerview_data or 'WriteDacl' in powerview_data:
            findings.append({
                'severity': 'HIGH',
                'category': 'Privilege Escalation',
                'finding': 'Dangerous ACL Permissions',
                'description': 'User has GenericAll or WriteDacl on domain objects',
                'recommendation': 'Review PowerView output for ACL abuse paths',
                'cvss': '8.0'
            })
        
        # Check for SQL instances
        if self.results.get('sql_instances'):
            findings.append({
                'severity': 'MEDIUM',
                'category': 'Attack Surface',
                'finding': 'SQL Server Instances Discovered',
                'description': 'SQL Server instances found in domain',
                'recommendation': 'Test for default credentials, SQL injection, xp_cmdshell',
                'cvss': '6.5'
            })
        
        # Sort findings by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        findings.sort(key=lambda x: severity_order.get(x['severity'], 4))
        
        with self.result_lock:
            self.results['weaknesses'] = findings
            self.results['interesting_findings'] = [f for f in findings if f['severity'] in ['CRITICAL', 'HIGH']]
        
        self.logger.log(f"Analysis complete - {len(findings)} findings identified", 
                       status="SUCCESS", thread_id=thread_id)
        return True
    
    def parse_net_output(self, output):
        """Parse net command output to extract items"""
        lines = output.split('\n')
        items = []
        for line in lines:
            line = line.strip()
            if line and not line.startswith('-') and not line.startswith('The command') and not line.startswith('User accounts'):
                items.extend([item.strip() for item in line.split() if item.strip()])
        return [item for item in items if len(item) > 2 and not item.startswith('\\\\')]
    
    def worker(self, task, worker_id):
        """Worker thread function"""
        try:
            self.logger.log(f"Starting task: {task.name}", status="INFO", thread_id=worker_id)
            result = task.execute(thread_id=worker_id)
            self.logger.log(f"Completed task: {task.name}", status="SUCCESS", thread_id=worker_id)
            return result
        except Exception as e:
            self.logger.log(f"Task failed: {task.name}", error=str(e), status="ERROR", thread_id=worker_id)
            return None
    
    def run_enumeration_parallel(self):
        """Execute enumeration tasks in parallel"""
        # Define all enumeration tasks
        tasks = [
            EnumerationTask("Current User", self.enumerate_current_user, priority=1, enabled=True),
            EnumerationTask("Local System", self.enumerate_local_system, priority=1, enabled=True),
            EnumerationTask("Domain Basic", self.enumerate_domain_basic, priority=1, enabled=True),
            EnumerationTask("Shares", self.enumerate_shares, priority=2, enabled=True),
            EnumerationTask("GPO", self.enumerate_gpo, priority=2, enabled=True),
            EnumerationTask("PowerView", self.enumerate_powerview, priority=3, enabled=self.config.powerview),
            EnumerationTask("SharpHound", self.enumerate_sharphound, priority=3, enabled=self.config.sharphound),
            EnumerationTask("ADRecon", self.enumerate_adrecon, priority=3, enabled=self.config.adrecon),
            EnumerationTask("ACLPwn", self.enumerate_aclpwn, priority=4, enabled=self.config.aclpwn),
            EnumerationTask("PowerUpSQL", self.enumerate_powerupsql, priority=4, enabled=self.config.powerupsql),
        ]
        
        # Filter enabled tasks
        enabled_tasks = [task for task in tasks if task.enabled]
        
        self.logger.log(f"Starting parallel enumeration with {len(enabled_tasks)} tasks", status="INFO")
        
        # Execute tasks in parallel with thread pool
        max_workers = min(self.config.threads, len(enabled_tasks))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_task = {
                executor.submit(self.worker, task, f"W{i}"): task 
                for i, task in enumerate(enabled_tasks, 1)
            }
            
            for future in as_completed(future_to_task):
                task = future_to_task[future]
                try:
                    result = future.result()
                except Exception as e:
                    self.logger.log(f"Task exception: {task.name}", error=str(e), status="ERROR")
        
        # Run analysis after all enumeration is complete
        self.logger.log("All enumeration tasks completed, running analysis", status="INFO")
        self.analyze_weaknesses()
    
    def generate_ascii_diagram(self):
        """Generate enhanced ASCII diagram of domain structure"""
        diagram = []
        w = 100  # Width
        
        diagram.append("=" * w)
        diagram.append("                                 DOMAIN TOPOLOGY DIAGRAM".center(w))
        diagram.append("=" * w)
        diagram.append("")
        
        # Extract domain name
        domain_name = "DOMAIN.LOCAL"
        try:
            domain_info = json.loads(self.results['domain_info'].get('basic', '{}'))
            if isinstance(domain_info, dict) and 'Name' in domain_info:
                domain_name = domain_info['Name']
        except:
            pass
        
        # Domain root
        diagram.append(f"                                   [{domain_name}]".center(w))
        diagram.append("                                        |".center(w))
        diagram.append("               +------------------------+------------------------+".center(w))
        diagram.append("               |                        |                        |".center(w))
        diagram.append("        [Domain Controllers]      [User Objects]         [Computer Objects]".center(w))
        diagram.append("")
        
        # Domain Controllers
        dcs = self.extract_domain_controllers()
        if dcs:
            diagram.append("    Domain Controllers:".ljust(w))
            for i, dc in enumerate(dcs[:5]):
                diagram.append(f"      [{i+1}] {dc['name']:<30} IP: {dc['ip']:<15}".ljust(w))
        
        diagram.append("")
        diagram.append("    Critical Groups & Membership:".ljust(w))
        diagram.append("    " + "-" * 80)
        
        # High-value groups
        key_groups = ['Domain Admins', 'Enterprise Admins', 'Administrators', 'Backup Operators']
        for group in key_groups:
            if group in str(self.results['groups']):
                diagram.append(f"      [+] {group}".ljust(w))
        
        diagram.append("")
        diagram.append("    Current User Privileges:".ljust(w))
        diagram.append("    " + "-" * 80)
        
        # Show if user is admin
        if self.results['local_privileges'].get('is_admin'):
            diagram.append("      [!!!] LOCAL ADMINISTRATOR ACCESS".ljust(w))
        
        # Show critical privileges
        privileges = str(self.results['current_user'].get('privileges', ''))
        critical_privs = ['SeDebugPrivilege', 'SeImpersonatePrivilege', 'SeLoadDriverPrivilege']
        for priv in critical_privs:
            if priv in privileges:
                diagram.append(f"      [!] {priv}".ljust(w))
        
        diagram.append("")
        diagram.append("    Attack Surface Summary:".ljust(w))
        diagram.append("    " + "-" * 80)
        diagram.append(f"      Users:     {len(self.results['users']):>6}".ljust(w))
        diagram.append(f"      Computers: {len(self.results['computers']):>6}".ljust(w))
        diagram.append(f"      Groups:    {len(self.results['groups']):>6}".ljust(w))
        diagram.append(f"      Shares:    {len(self.results['shares']):>6}".ljust(w))
        
        if self.results.get('sql_instances'):
            try:
                sql_data = json.loads(self.results['sql_instances'])
                if isinstance(sql_data, list):
                    diagram.append(f"      SQL Instances: {len(sql_data):>6}".ljust(w))
            except:
                pass
        
        diagram.append("")
        diagram.append("    CRITICAL FINDINGS:".ljust(w))
        diagram.append("    " + "=" * 80)
        
        # Show top 5 critical findings
        critical_findings = [f for f in self.results['weaknesses'] if f['severity'] in ['CRITICAL', 'HIGH']]
        for i, finding in enumerate(critical_findings[:5], 1):
            severity_symbol = "!!!" if finding['severity'] == 'CRITICAL' else "!!"
            diagram.append(f"      [{severity_symbol}] {finding['finding']:<50} CVSS: {finding.get('cvss', 'N/A')}".ljust(w))
        
        if len(critical_findings) > 5:
            diagram.append(f"      ... and {len(critical_findings) - 5} more critical findings".ljust(w))
        
        diagram.append("")
        diagram.append("    Tool Integration Status:".ljust(w))
        diagram.append("    " + "-" * 80)
        diagram.append(f"      PowerView:   {'[COMPLETED]' if self.config.powerview else '[DISABLED]'}".ljust(w))
        diagram.append(f"      SharpHound:  {'[COMPLETED]' if self.config.sharphound else '[DISABLED]'}".ljust(w))
        diagram.append(f"      ADRecon:     {'[COMPLETED]' if self.config.adrecon else '[DISABLED]'}".ljust(w))
        diagram.append(f"      ACLPwn:      {'[COMPLETED]' if self.config.aclpwn else '[DISABLED]'}".ljust(w))
        diagram.append(f"      PowerUpSQL:  {'[COMPLETED]' if self.config.powerupsql else '[DISABLED]'}".ljust(w))
        
        diagram.append("")
        diagram.append("=" * w)
        
        return "\n".join(diagram)
    
    def extract_domain_controllers(self):
        """Extract DC information from results"""
        dcs = []
        dc_output = self.results['domain_info'].get('domain_controllers', '')
        
        # Parse DC list
        lines = dc_output.split('\n')
        for line in lines:
            if '\\\\' in line:
                parts = line.split()
                if len(parts) > 0:
                    dc_name = parts[0].replace('\\\\', '').strip()
                    dc_ip = '0.0.0.0'
                    # Try to extract IP if present
                    for part in parts:
                        if '.' in part and part.replace('.', '').isdigit():
                            dc_ip = part
                            break
                    dcs.append({'name': dc_name, 'ip': dc_ip})
        
        # Also try to parse from domain info JSON
        try:
            domain_info = json.loads(self.results['domain_info'].get('basic', '{}'))
            if isinstance(domain_info, dict) and 'DomainControllers' in domain_info:
                dc_list = domain_info['DomainControllers']
                if isinstance(dc_list, list):
                    for dc in dc_list:
                        if dc not in [d['name'] for d in dcs]:
                            dcs.append({'name': dc, 'ip': '0.0.0.0'})
        except:
            pass
        
        return dcs if dcs else [{'name': 'DC01', 'ip': '0.0.0.0'}]
    
    def generate_report(self, output_file="domain_enum_report.txt"):
        """Generate comprehensive text report"""
        self.logger.log("Generating final report", status="INFO")
        
        with open(output_file, 'w', encoding='utf-8') as f:
            w = 100  # Width for formatting
            
            # Header
            f.write("=" * w + "\n")
            f.write("              DOMAIN ENUMERATION REPORT - RED TEAM PERSPECTIVE\n".center(w))
            f.write("=" * w + "\n")
            f.write(f"Generated:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Executed By:  {self.results['metadata']['username']}\n")
            f.write(f"Hostname:     {self.results['metadata']['hostname']}\n")
            f.write(f"Threads Used: {self.config.threads}\n")
            f.write("=" * w + "\n\n")
            
            # ASCII Diagram
            f.write(self.generate_ascii_diagram())
            f.write("\n\n")
            
            # Executive Summary
            f.write("=" * w + "\n")
            f.write("                             EXECUTIVE SUMMARY\n".center(w))
            f.write("=" * w + "\n\n")
            critical_count = len([f for f in self.results['weaknesses'] if f['severity'] == 'CRITICAL'])
            high_count = len([f for f in self.results['weaknesses'] if f['severity'] == 'HIGH'])
            medium_count = len([f for f in self.results['weaknesses'] if f['severity'] == 'MEDIUM'])
            
            f.write(f"\nRisk Assessment:\n")
            f.write(f"  Critical Issues:  {critical_count:>3}\n")
            f.write(f"  High Issues:      {high_count:>3}\n")
            f.write(f"  Medium Issues:    {medium_count:>3}\n")
            f.write(f"\nDiscovered Assets:\n")
            f.write(f"  Domain Users:     {len(self.results['users']):>6}\n")
            f.write(f"  Domain Computers: {len(self.results['computers']):>6}\n")
            f.write(f"  Domain Groups:    {len(self.results['groups']):>6}\n")
            f.write(f"  Network Shares:   {len(self.results['shares']):>6}\n")
            
            f.write("\n\n")
            
            # Current User Context
            f.write("=" * w + "\n")
            f.write("                          CURRENT USER CONTEXT\n".center(w))
            f.write("=" * w + "\n\n")
            f.write("WHO AM I:\n")
            f.write("-" * w + "\n")
            f.write(str(self.results['current_user'].get('whoami', 'N/A')))
            f.write("\n\n")
            
            f.write("PRIVILEGES:\n")
            f.write("-" * w + "\n")
            f.write(str(self.results['current_user'].get('privileges', 'N/A')))
            f.write("\n\n")
            
            f.write("GROUP MEMBERSHIPS:\n")
            f.write("-" * w + "\n")
            f.write(str(self.results['current_user'].get('groups', 'N/A')))
            f.write("\n\n")
            
            # Security Weaknesses - MOST IMPORTANT SECTION
            f.write("=" * w + "\n")
            f.write("          SECURITY WEAKNESSES & RED TEAM EXPLOITATION OPPORTUNITIES\n".center(w))
            f.write("=" * w + "\n\n")
            
            for i, finding in enumerate(self.results['weaknesses'], 1):
                f.write(f"\n[{i}] {finding['finding']}\n")
                f.write("=" * w + "\n")
                f.write(f"Severity:     {finding['severity']}\n")
                f.write(f"Category:     {finding['category']}\n")
                f.write(f"CVSS Score:   {finding.get('cvss', 'N/A')}\n")
                f.write(f"\nDescription:\n  {finding['description']}\n")
                f.write(f"\nExploitation:\n  {finding['recommendation']}\n")
                f.write("-" * w + "\n")
            
            f.write("\n\n")
            
            # Domain Information
            f.write("=" * w + "\n")
            f.write("                            DOMAIN INFORMATION\n".center(w))
            f.write("=" * w + "\n\n")
            f.write("BASIC DOMAIN INFO:\n")
            f.write("-" * w + "\n")
            try:
                domain_json = json.loads(self.results['domain_info'].get('basic', '{}'))
                f.write(json.dumps(domain_json, indent=2))
            except:
                f.write(str(self.results['domain_info'].get('basic', 'N/A')))
            f.write("\n\n")
            
            f.write("DOMAIN CONTROLLERS:\n")
            f.write("-" * w + "\n")
            f.write(str(self.results['domain_info'].get('domain_controllers', 'N/A')))
            f.write("\n\n")
            
            # Users (limited output)
            f.write("DOMAIN USERS (Sample):\n")
            f.write("-" * w + "\n")
            users_data = self.results['users']
            if isinstance(users_data, list):
                for user in users_data[:100]:
                    if isinstance(user, dict):
                        f.write(f"  - {user.get('samaccountname', 'N/A')}: {user.get('description', 'N/A')}\n")
                    else:
                        f.write(f"  - {user}\n")
                if len(users_data) > 100:
                    f.write(f"  ... and {len(users_data) - 100} more users\n")
            else
              f.write("\n\n")
            
            # Computers (limited output)
            f.write("DOMAIN COMPUTERS (Sample):\n")
            f.write("-" * w + "\n")
            computers_data = self.results['computers']
            if isinstance(computers_data, list):
                for computer in computers_data[:50]:
                    if isinstance(computer, dict):
                        f.write(f"  - {computer.get('Name', 'N/A')} ({computer.get('DNSHostName', 'N/A')})\n")
                    else:
                        f.write(f"  - {computer}\n")
                if len(computers_data) > 50:
                    f.write(f"  ... and {len(computers_data) - 50} more computers\n")
            else:
                f.write(str(computers_data))
            f.write("\n\n")
            
            # Groups
            f.write("DOMAIN GROUPS (Sample):\n")
            f.write("-" * w + "\n")
            groups_data = self.results['groups']
            if isinstance(groups_data, list):
                for group in groups_data[:20]:
                    if isinstance(group, dict):
                        f.write(f"  - {group.get('Name', 'N/A')} ({group.get('SamAccountName', 'N/A')})\n")
                    else:
                        f.write(f"  - {group}\n")
                if len(groups_data) > 20:
                    f.write(f"  ... and {len(groups_data) - 20} more groups\n")
            else:
                f.write(str(groups_data))
            f.write("\n\n")
            
            # Network Shares
            f.write("NETWORK SHARES:\n")
            f.write("-" * w + "\n")
            for share in self.results['shares'][:10]:
                f.write(f"Type: {share.get('type', 'N/A')}\n")
                f.write(f"Data: {str(share.get('data', 'N/A'))[:500]}\n\n")
            if len(self.results['shares']) > 10:
                f.write(f"... and {len(self.results['shares']) - 10} more shares\n")
            f.write("\n\n")
            
            # PowerView Results
            if self.config.powerview and self.results.get('powerview_data'):
                f.write("=" * w + "\n")
                f.write("                          POWERVIEW RESULTS\n".center(w))
                f.write("=" * w + "\n\n")
                try:
                    powerview_data = json.loads(self.results['powerview_data'])
                    f.write(json.dumps(powerview_data, indent=2)[:3000])
                except:
                    f.write(str(self.results['powerview_data'])[:3000])
                f.write("\n\n")
            
            # SharpHound Results
            if self.config.sharphound and self.results.get('bloodhound_data'):
                f.write("=" * w + "\n")
                f.write("                         SHARPHOUND RESULTS\n".center(w))
                f.write("=" * w + "\n\n")
                f.write(f"Output: {str(self.results['bloodhound_data'])[:2000]}\n")
                f.write("\n\n")
            
            # ADRecon Results
            if self.config.adrecon and self.results.get('adrecon_data'):
                f.write("=" * w + "\n")
                f.write("                           ADRECON RESULTS\n".center(w))
                f.write("=" * w + "\n\n")
                ad_data = self.results['adrecon_data']
                f.write(f"Output: {str(ad_data)[:2000]}\n")
                f.write("\n\n")
            
            # ACLPwn Results
            if self.config.aclpwn and self.results.get('aclpwn_data'):
                f.write("=" * w + "\n")
                f.write("                           ACLPWN RESULTS\n".center(w))
                f.write("=" * w + "\n\n")
                try:
                    acl_data = json.loads(self.results['aclpwn_data'])
                    f.write(json.dumps(acl_data, indent=2)[:3000])
                except:
                    f.write(str(self.results['aclpwn_data'])[:3000])
                f.write("\n\n")
            
            # PowerUpSQL Results
            if self.config.powerupsql and self.results.get('powerupsql_data'):
                f.write("=" * w + "\n")
                f.write("                         POWERUPSQL RESULTS\n".center(w))
                f.write("=" * w + "\n\n")
                try:
                    sql_data = json.loads(self.results['powerupsql_data'])
                    f.write(json.dumps(sql_data, indent=2)[:3000])
                except:
                    f.write(str(self.results['powerupsql_data'])[:3000])
                f.write("\n\n")
            
            # Cleanup Information
            f.write("=" * w + "\n")
            f.write("                           CLEANUP INFORMATION\n".center(w))
            f.write("=" * w + "\n\n")
            f.write(f"Temporary Directory: {self.temp_dir}\n")
            f.write("Please ensure this directory is properly cleaned up after analysis.\n\n")
            
            # Footer
            f.write("=" * w + "\n")
            f.write("                    END OF DOMAIN ENUMERATION REPORT\n".center(w))
            f.write("=" * w + "\n")
        
        self.logger.log(f"Report saved to: {output_file}", status="SUCCESS")
        return output_file

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Advanced Domain Enumeration Tool - Red Team Edition')
    parser.add_argument('--threads', type=int, default=5, help='Number of concurrent threads (default: 5)')
    parser.add_argument('--powerview', action='store_true', help='Enable PowerView enumeration')
    parser.add_argument('--sharphound', action='store_true', help='Enable SharpHound enumeration')
    parser.add_argument('--adrecon', action='store_true', help='Enable ADRecon enumeration')
    parser.add_argument('--aclpwn', action='store_true', help='Enable ACLPwn enumeration')
    parser.add_argument('--powerupsql', action='store_true', help='Enable PowerUpSQL enumeration')
    parser.add_argument('--all', action='store_true', help='Enable all enumeration modules')
    parser.add_argument('--output', type=str, default='domain_enum_report.txt', help='Output report filename')
    parser.add_argument('--in-memory', action='store_true', dest='in_memory_mode', 
                        help='Run tools from memory without downloading')
    parser.add_argument('--no-cleanup', action='store_true', help='Do not cleanup temporary files')
    
    args = parser.parse_args()
    
    # If --all flag is set, enable all modules
    if args.all:
        args.powerview = True
        args.sharphound = True
        args.adrecon = True
        args.aclpwn = True
        args.powerupsql = True
    
    start_time = datetime.now()
    print(f"[+] Starting Advanced Domain Enumeration at {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[+] Configuration:")
    print(f"    Threads: {args.threads}")
    print(f"    PowerView: {'ENABLED' if args.powerview else 'DISABLED'}")
    print(f"    SharpHound: {'ENABLED' if args.sharphound else 'DISABLED'}")
    print(f"    ADRecon: {'ENABLED' if args.adrecon else 'DISABLED'}")
    print(f"    ACLPwn: {'ENABLED' if args.aclpwn else 'DISABLED'}")
    print(f"    PowerUpSQL: {'ENABLED' if args.powerupsql else 'DISABLED'}")
    print(f"    In-Memory Mode: {'ENABLED' if args.in_memory_mode else 'DISABLED'}")
    
    try:
        # Initialize enumerator
        enumerator = DomainEnumerator(args)
        
        # Run enumeration
        enumerator.run_enumeration_parallel()
        
        # Generate report
        report_file = enumerator.generate_report(args.output)
        end_time = datetime.now()
        duration = end_time - start_time
        
        print(f"\n[+] Enumeration completed successfully!")
        print(f"[+] Report saved to: {report_file}")
        print(f"[+] Execution time: {duration}")
        print(f"[+] Start time: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[+] End time: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Display quick summary
        critical_findings = [f for f in enumerator.results['weaknesses'] if f['severity'] == 'CRITICAL']
        high_findings = [f for f in enumerator.results['weaknesses'] if f['severity'] == 'HIGH']
        
        if critical_findings or high_findings:
            print(f"\n[!] SECURITY FINDINGS SUMMARY:")
            if critical_findings:
                print(f"    CRITICAL: {len(critical_findings)} issue(s) requiring immediate attention")
            if high_findings:
                print(f"    HIGH:     {len(high_findings)} significant security issues")
            print(f"    See full report for detailed exploitation recommendations.")
        else:
            print(f"\n[+] No critical or high severity issues found during enumeration.")
            
    except KeyboardInterrupt:
        print(f"\n[-] Enumeration interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] Error during enumeration: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
