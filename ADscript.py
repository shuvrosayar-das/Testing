#!/usr/bin/env python3
"""
Advanced Domain Enumeration Tool - Integrated Red Team Edition
Complete implementation with all tools embedded
No external dependencies required
Version: 2.0 - Complete Release
Author: Security Research Team
License: For Authorized Security Testing Only
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
import socket
import struct
import re
import base64
import hashlib
from collections import defaultdict

# Optional library imports with graceful fallbacks
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False

try:
    import win32security
    import win32api
    import win32con
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False


class Config:
    """Configuration management for the enumeration tool"""
    def __init__(self):
        self.target_domain = None
        self.target_dc = None
        self.target_hosts = []
        self.username = None
        self.password = None
        self.domain = None
        self.ntlm_hash = None
        self.modules = {
            'reconnaissance': True,
            'host_enum': True,
            'privilege_escalation': True,
            'credential_access': True,
            'lateral_movement': False,
            'domain_enum': True,
            'vulnerability_assessment': True,
            'persistence_check': False,
        }
        self.max_threads = 5
        self.timeout = 300
        self.verbose = False
        self.output_dir = 'output'
        self.stealth_mode = False
        self.use_embedded_tools = True
        self.test_categories = []
        self.skip_tests = []

    def from_args(self, args):
        """Load configuration from command line arguments"""
        self.target_domain = args.domain
        self.target_dc = args.dc
        self.username = args.username
        self.password = args.password
        self.domain = args.domain
        self.ntlm_hash = args.hash
        
        if args.modules:
            for module in self.modules:
                self.modules[module] = module in args.modules
        
        self.max_threads = args.threads
        self.timeout = args.timeout
        self.verbose = args.verbose
        self.output_dir = args.output
        self.stealth_mode = args.stealth
        
        if args.targets_file:
            self.load_targets_file(args.targets_file)
        
        if args.skip_tests:
            self.skip_tests = args.skip_tests.split(',')
        
        if args.categories:
            self.test_categories = args.categories.split(',')
    
    def load_targets_file(self, filepath):
        """Load target hosts from file"""
        try:
            with open(filepath, 'r') as f:
                self.target_hosts = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[!] Error loading targets file: {e}")


class Logger:
    """Advanced logging with color support and structured output"""
    
    COLORS = {
        'INFO': '\033[94m',
        'SUCCESS': '\033[92m',
        'WARN': '\033[93m',
        'ERROR': '\033[91m',
        'CRITICAL': '\033[95m',
        'RESET': '\033[0m'
    }
    
    def __init__(self, output_dir='output', verbose=False):
        self.output_dir = output_dir
        self.verbose = verbose
        self.lock = threading.Lock()
        self.logs = []
        
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.log_file = os.path.join(output_dir, f'enumeration_{timestamp}.log')
        self.json_file = os.path.join(output_dir, f'results_{timestamp}.json')
        self.testcase_file = os.path.join(output_dir, f'testcases_{timestamp}.txt')
    
    def log(self, message, status="INFO", error="", command="", thread_id="", test_id=""):
        """Log a message with structured data"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        log_entry = {
            'timestamp': timestamp,
            'status': status,
            'message': message,
            'thread_id': thread_id,
            'test_id': test_id
        }
        
        if error:
            log_entry['error'] = error
        if command:
            log_entry['command'] = command
        
        with self.lock:
            self.logs.append(log_entry)
            
            color = self.COLORS.get(status, '')
            reset = self.COLORS['RESET']
            
            console_msg = f"{color}[{status}]{reset} [{timestamp}]"
            if thread_id:
                console_msg += f" [T:{thread_id}]"
            if test_id:
                console_msg += f" [TC:{test_id}]"
            console_msg += f" {message}"
            
            if error and (self.verbose or status == "ERROR"):
                console_msg += f"\n  └─ Error: {error}"
            
            print(console_msg)
            
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(f"{json.dumps(log_entry)}\n")
    
    def save_results(self, results):
        """Save results to JSON file"""
        with self.lock:
            with open(self.json_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, default=str)
    
    def save_testcase_report(self, testcases):
        """Save test case report to text file"""
        with self.lock:
            with open(self.testcase_file, 'w', encoding='utf-8') as f:
                f.write("="*80 + "\n")
                f.write("RED TEAM ENUMERATION - TEST CASE REPORT\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*80 + "\n\n")
                
                for tc in testcases:
                    f.write(f"Test Case ID: {tc['id']}\n")
                    f.write(f"Category: {tc['category']}\n")
                    f.write(f"Name: {tc['name']}\n")
                    f.write(f"Status: {tc['status']}\n")
                    f.write(f"Description: {tc['description']}\n")
                    
                    if tc.get('reason'):
                        f.write(f"Reason: {tc['reason']}\n")
                    
                    if tc.get('output'):
                        f.write(f"Output Snippet:\n")
                        output = tc['output'][:500] if len(tc['output']) > 500 else tc['output']
                        f.write(f"  {output}\n")
                    
                    if tc.get('findings'):
                        f.write(f"Findings:\n")
                        for finding in tc['findings']:
                            f.write(f"  - {finding}\n")
                    
                    f.write("-"*80 + "\n\n")


class TestCase:
    """Base class for test cases"""
    def __init__(self, test_id, name, category, description, requires_creds=False, 
                 requires_admin=False, risk_level="LOW"):
        self.id = test_id
        self.name = name
        self.category = category
        self.description = description
        self.requires_creds = requires_creds
        self.requires_admin = requires_admin
        self.risk_level = risk_level
        self.status = "PENDING"
        self.output = ""
        self.findings = []
        self.reason = ""
    
    def can_run(self, config, is_admin=False):
        """Check if test case can run with current config"""
        if self.requires_creds and not (config.username and config.password):
            self.status = "SKIPPED"
            self.reason = "Requires credentials"
            return False
        
        if self.requires_admin and not is_admin:
            self.status = "SKIPPED"
            self.reason = "Requires administrative privileges"
            return False
        
        return True
    
    def to_dict(self):
        """Convert test case to dictionary"""
        return {
            'id': self.id,
            'name': self.name,
            'category': self.category,
            'description': self.description,
            'status': self.status,
            'reason': self.reason,
            'output': self.output,
            'findings': self.findings,
            'risk_level': self.risk_level
        }


class EmbeddedTools:
    """Container for all embedded tool implementations"""
    
    @staticmethod
    def get_system_info():
        """Get basic system information"""
        info = {
            'hostname': socket.gethostname(),
            'os': sys.platform,
            'python_version': sys.version
        }
        
        try:
            info['username'] = os.getenv('USERNAME') or os.getenv('USER')
            info['computername'] = os.getenv('COMPUTERNAME') or socket.gethostname()
            info['domain'] = os.getenv('USERDOMAIN') or 'WORKGROUP'
        except:
            pass
        
        if HAS_PSUTIL:
            try:
                info['cpu_count'] = psutil.cpu_count()
                info['memory_total'] = psutil.virtual_memory().total
                info['boot_time'] = datetime.fromtimestamp(psutil.boot_time()).isoformat()
            except:
                pass
        
        return info
    
    @staticmethod
    def enumerate_local_users():
        """Enumerate local users"""
        users = []
        
        if sys.platform == 'win32':
            try:
                result = subprocess.run(['net', 'user'], capture_output=True, text=True, timeout=30)
                lines = result.stdout.split('\n')
                in_user_section = False
                
                for line in lines:
                    if '---' in line:
                        in_user_section = True
                        continue
                    if in_user_section and line.strip():
                        users.extend([u.strip() for u in line.split() if u.strip()])
            except:
                pass
        
        return users
    
    @staticmethod
    def enumerate_local_groups():
        """Enumerate local groups"""
        groups = {}
        
        if sys.platform == 'win32':
            try:
                result = subprocess.run(['net', 'localgroup'], capture_output=True, text=True, timeout=30)
                
                for line in result.stdout.split('\n'):
                    if line.startswith('*'):
                        group_name = line.replace('*', '').strip()
                        groups[group_name] = []
            except:
                pass
        
        return groups
    
    @staticmethod
    def check_admin_privileges():
        """Check if running with admin privileges"""
        if sys.platform == 'win32':
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                return False
        else:
            return os.geteuid() == 0
    
    @staticmethod
    def enumerate_processes():
        """Enumerate running processes"""
        processes = []
        
        if HAS_PSUTIL:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'username']):
                    try:
                        processes.append(proc.info)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            except:
                pass
        elif sys.platform == 'win32':
            try:
                result = subprocess.run(['tasklist', '/FO', 'CSV', '/NH'], capture_output=True, text=True, timeout=30)
                
                for line in result.stdout.split('\n'):
                    if line.strip():
                        parts = line.split(',')
                        if len(parts) >= 2:
                            processes.append({'name': parts[0].strip('"'), 'pid': parts[1].strip('"')})
            except:
                pass
        
        return processes
    
    @staticmethod
    def detect_av_edr():
        """Detect AV/EDR products"""
        av_products = []
        av_processes = [
            'MsMpEng.exe', 'mcshield.exe', 'avp.exe', 'avgcsrvx.exe',
            'CylanceSvc.exe', 'CSFalconService.exe', 'cb.exe',
            'SentinelAgent.exe', 'elastic-agent.exe', 'taniumclient.exe',
            'SophosHealth.exe', 'SAVService.exe'
        ]
        
        processes = EmbeddedTools.enumerate_processes()
        
        for proc in processes:
            proc_name = proc.get('name', '')
            if any(av in proc_name for av in av_processes):
                av_products.append(proc_name)
        
        return list(set(av_products))
    
    @staticmethod
    def enumerate_network_interfaces():
        """Enumerate network interfaces"""
        interfaces = []
        
        if HAS_PSUTIL:
            try:
                for iface, addrs in psutil.net_if_addrs().items():
                    iface_info = {'name': iface, 'addresses': []}
                    for addr in addrs:
                        iface_info['addresses'].append({'family': str(addr.family), 'address': addr.address})
                    interfaces.append(iface_info)
            except:
                pass
        elif sys.platform == 'win32':
            try:
                result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True, timeout=30)
                interfaces.append({'raw_output': result.stdout})
            except:
                pass
        
        return interfaces
    
    @staticmethod
    def enumerate_services():
        """Enumerate Windows services"""
        services = []
        
        if sys.platform == 'win32':
            try:
                result = subprocess.run(['sc', 'query', 'type=', 'service', 'state=', 'all'], 
                                      capture_output=True, text=True, timeout=60)
                
                current_service = {}
                for line in result.stdout.split('\n'):
                    if 'SERVICE_NAME:' in line:
                        if current_service:
                            services.append(current_service)
                        current_service = {'name': line.split('SERVICE_NAME:')[1].strip()}
                    elif 'DISPLAY_NAME:' in line and current_service:
                        current_service['display_name'] = line.split('DISPLAY_NAME:')[1].strip()
                    elif 'STATE' in line and current_service:
                        current_service['state'] = line.split(':')[1].strip()
                
                if current_service:
                    services.append(current_service)
            except:
                pass
        
        return services
    
    @staticmethod
    def find_interesting_files(search_paths=None, patterns=None):
        """Search for interesting files"""
        if not search_paths:
            if sys.platform == 'win32':
                search_paths = [os.path.expandvars('%USERPROFILE%'), os.path.expandvars('%APPDATA%')]
            else:
                search_paths = [os.path.expanduser('~')]
        
        if not patterns:
            patterns = ['*password*', '*config*', '*.kdbx', '*credential*', '*.key']
        
        interesting_files = []
        
        for search_path in search_paths:
            try:
                for root, dirs, files in os.walk(search_path):
                    if any(skip in root.lower() for skip in ['windows', 'system32', 'program files']):
                        continue
                    
                    for file in files:
                        file_lower = file.lower()
                        if any(pattern.strip('*') in file_lower for pattern in patterns):
                            interesting_files.append(os.path.join(root, file))
                    
                    if root.count(os.sep) - search_path.count(os.sep) > 3:
                        break
                        
            except (PermissionError, OSError):
                continue
        
        return interesting_files[:100]
    
    @staticmethod
    def enumerate_scheduled_tasks():
        """Enumerate scheduled tasks"""
        tasks = []
        
        if sys.platform == 'win32':
            try:
                result = subprocess.run(['schtasks', '/query', '/fo', 'LIST', '/v'], 
                                      capture_output=True, text=True, timeout=60)
                
                current_task = {}
                for line in result.stdout.split('\n'):
                    if 'TaskName:' in line:
                        if current_task:
                            tasks.append(current_task)
                        current_task = {'name': line.split('TaskName:')[1].strip()}
                    elif 'Task To Run:' in line and current_task:
                        current_task['command'] = line.split('Task To Run:')[1].strip()
                    elif 'Status:' in line and current_task:
                        current_task['status'] = line.split('Status:')[1].strip()
                
                if current_task:
                    tasks.append(current_task)
            except:
                pass
        
        return tasks
    
    @staticmethod
    def check_uac_level():
        """Check UAC configuration"""
        uac_info = {}
        
        if sys.platform == 'win32' and HAS_WINREG:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                    r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System')
                
                try:
                    consent_prompt, _ = winreg.QueryValueEx(key, 'ConsentPromptBehaviorAdmin')
                    uac_info['consent_prompt_level'] = consent_prompt
                except:
                    pass
                
                try:
                    enable_lua, _ = winreg.QueryValueEx(key, 'EnableLUA')
                    uac_info['uac_enabled'] = enable_lua == 1
                except:
                    pass
                
                winreg.CloseKey(key)
            except:
                pass
        
        return uac_info
    
    @staticmethod
    def enumerate_registry_autoruns():
        """Enumerate autorun registry keys"""
        autoruns = []
        
        if sys.platform == 'win32' and HAS_WINREG:
            autorun_keys = [
                (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Run'),
                (winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
                (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\Run'),
                (winreg.HKEY_LOCAL_MACHINE, r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
            ]
            
            for hive, key_path in autorun_keys:
                try:
                    key = winreg.OpenKey(hive, key_path)
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            autoruns.append({
                                'hive': 'HKCU' if hive == winreg.HKEY_CURRENT_USER else 'HKLM',
                                'path': key_path,
                                'name': name,
                                'value': value
                            })
                            i += 1
                        except WindowsError:
                            break
                    winreg.CloseKey(key)
                except:
                    pass
        
        return autoruns
    
    @staticmethod
    def enumerate_shares():
        """Enumerate network shares"""
        shares = []
        
        if sys.platform == 'win32':
            try:
                result = subprocess.run(['net', 'share'], capture_output=True, text=True, timeout=30)
                
                for line in result.stdout.split('\n'):
                    if line.strip() and not line.startswith('-') and not line.startswith('Share name'):
                        parts = line.split()
                        if len(parts) >= 2:
                            shares.append({'name': parts[0], 'path': ' '.join(parts[1:])})
            except:
                pass
        
        return shares
    
    @staticmethod
    def check_powershell_logging():
        """Check PowerShell logging configuration"""
        logging_config = {}
        
        if sys.platform == 'win32' and HAS_WINREG:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                    r'SOFTWARE\Policies\Microsoft\Windows\PowerShell')
                
                try:
                    subkey = winreg.OpenKey(key, 'ScriptBlockLogging')
                    enabled, _ = winreg.QueryValueEx(subkey, 'EnableScriptBlockLogging')
                    logging_config['script_block_logging'] = enabled == 1
                    winreg.CloseKey(subkey)
                except:
                    logging_config['script_block_logging'] = False
                
                winreg.CloseKey(key)
            except:
                pass
        
        return logging_config


class HostReconTests:
    """Host reconnaissance test cases"""
    
    @staticmethod
    def create_tests():
        tests = []
        tests.append(TestCase('HR-001', 'System Information Enumeration', 'Host Reconnaissance',
                             'Gather basic system information including OS, hostname, and configuration'))
        tests.append(TestCase('HR-002', 'Local User Enumeration', 'Host Reconnaissance',
                             'Enumerate all local user accounts on the system'))
        tests.append(TestCase('HR-003', 'Local Group Enumeration', 'Host Reconnaissance',
                             'Enumerate local groups and their members'))
        tests.append(TestCase('HR-004', 'Administrative Privilege Check', 'Host Reconnaissance',
                             'Determine if current user has administrative privileges'))
        tests.append(TestCase('HR-005', 'Running Process Enumeration', 'Host Reconnaissance',
                             'List all running processes and their owners'))
        tests.append(TestCase('HR-006', 'Security Product Detection', 'Host Reconnaissance',
                             'Detect presence of AV/EDR security products', risk_level='HIGH'))
        tests.append(TestCase('HR-007', 'Network Interface Enumeration', 'Host Reconnaissance',
                             'Enumerate all network interfaces and their configurations'))
        tests.append(TestCase('HR-008', 'Windows Service Enumeration', 'Host Reconnaissance',
                             'List all Windows services and their states'))
        return tests


class PrivilegeEscalationTests:
    """Privilege escalation test cases"""
    
    @staticmethod
    def create_tests():
        tests = []
        tests.append(TestCase('PE-001', 'Service Permission Audit', 'Privilege Escalation',
                             'Check for services with weak permissions', risk_level='MEDIUM'))
        tests.append(TestCase('PE-002', 'Unquoted Service Path Detection', 'Privilege Escalation',
                             'Find services with unquoted paths containing spaces', risk_level='MEDIUM'))
        tests.append(TestCase('PE-003', 'UAC Configuration Assessment', 'Privilege Escalation',
                             'Assess User Account Control configuration', risk_level='MEDIUM'))
        tests.append(TestCase('PE-004', 'Scheduled Task Analysis', 'Privilege Escalation',
                             'Enumerate scheduled tasks for privilege escalation opportunities', risk_level='MEDIUM'))
        tests.append(TestCase('PE-005', 'Autorun Registry Keys', 'Privilege Escalation',
                             'Enumerate registry autorun keys for persistence vectors', risk_level='LOW'))
        return tests


class CredentialAccessTests:
    """Credential access test cases"""
    
    @staticmethod
    def create_tests():
        tests = []
        tests.append(TestCase('CA-001', 'Credential File Discovery', 'Credential Access',
                             'Search for files potentially containing credentials', risk_level='MEDIUM'))
        tests.append(TestCase('CA-002', 'Browser Credential Store Detection', 'Credential Access',
                             'Detect browser credential storage locations', risk_level='MEDIUM'))
        tests.append(TestCase('CA-003', 'WiFi Password Extraction', 'Credential Access',
                             'Extract saved WiFi passwords', risk_level='MEDIUM'))
        tests.append(TestCase('CA-004', 'RDP Saved Credential Detection', 'Credential Access',
                             'Check for saved RDP credentials', risk_level='LOW'))
        return tests


class PersistenceTests:
    """Persistence mechanism test cases"""
    
    @staticmethod
    def create_tests():
        tests = []
        tests.append(TestCase('PS-001', 'Startup Folder Analysis', 'Persistence',
                             'Enumerate startup folder contents', risk_level='LOW'))
        tests.append(TestCase('PS-002', 'Service-Based Persistence Detection', 'Persistence',
                             'Check for suspicious services that could be used for persistence', risk_level='LOW'))
        return tests


class NetworkTests:
    """Network enumeration test cases"""
    
    @staticmethod
    def create_tests():
        tests = []
        tests.append(TestCase('NT-001', 'Network Share Enumeration', 'Network',
                             'Enumerate accessible network shares', risk_level='LOW'))
        tests.append(TestCase('NT-002', 'Local Port Enumeration', 'Network',
                             'Enumerate open ports on local system', risk_level='LOW'))
        return tests


class DefenseEvasionTests:
    """Defense evasion test cases"""
    
    @staticmethod
    def create_tests():
        tests = []
        tests.append(TestCase('DE-001', 'PowerShell Logging Configuration', 'Defense Evasion',
                             'Check PowerShell logging and transcript configuration', risk_level='LOW'))
        tests.append(TestCase('DE-002', 'Windows Defender Status Check', 'Defense Evasion',
                             'Check Windows Defender real-time protection status', risk_level='MEDIUM'))
        return tests


class AdvancedHostTests:
    """Advanced host enumeration tests"""
    
    @staticmethod
    def create_tests():
        tests = []
        tests.append(TestCase('AH-001', 'Installed Software Enumeration', 'Host Reconnaissance',
                             'Enumerate installed software and versions'))
        tests.append(TestCase('AH-002', 'Environment Variable Enumeration', 'Host Reconnaissance',
                             'Extract environment variables for sensitive information'))
        tests.append(TestCase('AH-003', 'Clipboard Content Check', 'Host Reconnaissance',
                             'Check clipboard for sensitive information', risk_level='HIGH'))
        return tests


class FileSystemTests:
    """File system enumeration tests"""
    
    @staticmethod
    def create_tests():
        tests = []
        tests.append(TestCase('FS-001', 'World-Writable Directory Discovery', 'Privilege Escalation',
                             'Find directories with weak permissions', risk_level='MEDIUM'))
        tests.append(TestCase('FS-002', 'Recent Files Analysis', 'Credential Access',
                             'Analyze recently accessed files', risk_level='LOW'))
        return tests


class TestExecutor:
    """Executes test cases and collects results"""
    
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.tools = EmbeddedTools()
        self.is_admin = self.tools.check_admin_privileges()
        self.results = defaultdict(list)
        self.test_queue = queue.Queue()
        self.test_results = []
    
    def execute_host_recon_test(self, test):
        """Execute host reconnaissance tests"""
        try:
            if test.id == 'HR-001':
                info = self.tools.get_system_info()
                test.output = json.dumps(info, indent=2)
                test.findings = [
                    f"Hostname: {info.get('hostname', 'Unknown')}",
                    f"OS: {info.get('os', 'Unknown')}",
                    f"User: {info.get('username', 'Unknown')}",
                    f"Domain: {info.get('domain', 'Unknown')}"
                ]
                test.status = "COMPLETED"
                
            elif test.id == 'HR-002':
                users = self.tools.enumerate_local_users()
                test.output = '\n'.join(users)
                test.findings = [f"Found {len(users)} local users"]
                if users:
                    test.findings.extend(users[:10])
                test.status = "COMPLETED"
                
            elif test.id == 'HR-003':
                groups = self.tools.enumerate_local_groups()
                test.output = json.dumps(groups, indent=2)
                test.findings = [f"Found {len(groups)} local groups"]
                test.findings.extend(list(groups.keys())[:10])
                test.status = "COMPLETED"
                
            elif test.id == 'HR-004':
                is_admin = self.is_admin
                test.output = f"Administrative privileges: {is_admin}"
                test.findings = [
                    f"Running as Administrator: {is_admin}",
                    "HIGH RISK: Administrative access detected" if is_admin else "Standard user privileges"
                ]
                test.status = "COMPLETED"
                
            elif test.id == 'HR-005':
                processes = self.tools.enumerate_processes()
                test.output = json.dumps(processes[:50], indent=2)
                test.findings = [f"Found {len(processes)} running processes"]
                
                interesting = ['lsass.exe', 'winlogon.exe', 'svchost.exe']
                for proc in processes:
                    if proc.get('name', '').lower() in interesting:
                        test.findings.append(f"Interesting process: {proc.get('name')}")
                
                test.status = "COMPLETED"
                
            elif test.id == 'HR-006':
                                av_products = self.tools.detect_av_edr()
                test.output = '\n'.join(av_products) if av_products else "No AV/EDR detected"
                
                if av_products:
                    test.findings = [f"DETECTED: {av}" for av in av_products]
                    test.findings.insert(0, f"Found {len(av_products)} security products")
                else:
                    test.findings = ["No AV/EDR products detected"]
                
                test.status = "COMPLETED"
                
            elif test.id == 'HR-007':
                interfaces = self.tools.enumerate_network_interfaces()
                test.output = json.dumps(interfaces, indent=2)
                test.findings = [f"Found {len(interfaces)} network interfaces"]
                
                for iface in interfaces[:5]:
                    test.findings.append(f"Interface: {iface.get('name', 'Unknown')}")
                
                test.status = "COMPLETED"
                
            elif test.id == 'HR-008':
                services = self.tools.enumerate_services()
                test.output = json.dumps(services[:50], indent=2)
                test.findings = [f"Found {len(services)} services"]
                
                running = sum(1 for s in services if 'RUNNING' in s.get('state', ''))
                test.findings.append(f"Running services: {running}")
                
                test.status = "COMPLETED"
                
        except Exception as e:
            test.status = "ERROR"
            test.reason = str(e)
            self.logger.log(f"Test {test.id} failed", error=str(e), status="ERROR", test_id=test.id)
    
    def execute_privesc_test(self, test):
        """Execute privilege escalation tests"""
        try:
            if test.id == 'PE-001':
                services = self.tools.enumerate_services()
                test.output = f"Analyzed {len(services)} services for permission issues"
                test.findings = [f"Total services: {len(services)}", "Manual review required for detailed permission analysis"]
                test.status = "COMPLETED"
                
            elif test.id == 'PE-002':
                services = self.tools.enumerate_services()
                vulnerable = []
                
                for service in services:
                    name = service.get('name', '')
                    if ' ' in name and not (name.startswith('"') or name.startswith("'")):
                        vulnerable.append(service)
                
                test.output = json.dumps(vulnerable, indent=2)
                test.findings = [f"Found {len(vulnerable)} potentially vulnerable services"]
                
                for vuln in vulnerable[:5]:
                    test.findings.append(f"Vulnerable: {vuln.get('name', 'Unknown')}")
                
                test.status = "COMPLETED"
                
            elif test.id == 'PE-003':
                uac_info = self.tools.check_uac_level()
                test.output = json.dumps(uac_info, indent=2)
                
                if uac_info.get('uac_enabled'):
                    test.findings = ["UAC is enabled", f"Consent prompt level: {uac_info.get('consent_prompt_level', 'Unknown')}"]
                else:
                    test.findings = ["WARNING: UAC appears to be disabled", "Privilege escalation may be easier"]
                
                test.status = "COMPLETED"
                
            elif test.id == 'PE-004':
                tasks = self.tools.enumerate_scheduled_tasks()
                test.output = json.dumps(tasks[:20], indent=2)
                test.findings = [f"Found {len(tasks)} scheduled tasks"]
                
                for task in tasks:
                    cmd = task.get('command', '').lower()
                    if any(keyword in cmd for keyword in ['powershell', 'cmd', 'script']):
                        test.findings.append(f"Interesting: {task.get('name', 'Unknown')}")
                
                test.status = "COMPLETED"
                
            elif test.id == 'PE-005':
                autoruns = self.tools.enumerate_registry_autoruns()
                test.output = json.dumps(autoruns, indent=2)
                test.findings = [f"Found {len(autoruns)} autorun entries"]
                
                for entry in autoruns[:10]:
                    test.findings.append(f"{entry['hive']}\\{entry['name']}")
                
                test.status = "COMPLETED"
                
        except Exception as e:
            test.status = "ERROR"
            test.reason = str(e)
            self.logger.log(f"Test {test.id} failed", error=str(e), status="ERROR", test_id=test.id)
    
    def execute_credential_test(self, test):
        """Execute credential access tests"""
        try:
            if test.id == 'CA-001':
                interesting_files = self.tools.find_interesting_files()
                test.output = '\n'.join(interesting_files[:50])
                test.findings = [f"Found {len(interesting_files)} potentially interesting files"]
                
                for file in interesting_files[:10]:
                    test.findings.append(f"File: {file}")
                
                test.status = "COMPLETED"
                
            elif test.id == 'CA-002':
                findings = []
                
                if sys.platform == 'win32':
                    chrome_path = os.path.join(os.getenv('LOCALAPPDATA', ''), 'Google', 'Chrome', 'User Data', 'Default', 'Login Data')
                    if os.path.exists(chrome_path):
                        findings.append(f"Chrome credential DB found: {chrome_path}")
                    
                    firefox_path = os.path.join(os.getenv('APPDATA', ''), 'Mozilla', 'Firefox', 'Profiles')
                    if os.path.exists(firefox_path):
                        findings.append(f"Firefox profile directory found: {firefox_path}")
                
                test.output = '\n'.join(findings)
                test.findings = findings if findings else ["No browser credential stores detected"]
                test.status = "COMPLETED"
                
            elif test.id == 'CA-003':
                if sys.platform == 'win32':
                    try:
                        result = subprocess.run(['netsh', 'wlan', 'show', 'profiles'], capture_output=True, text=True, timeout=30)
                        
                        profiles = []
                        for line in result.stdout.split('\n'):
                            if 'All User Profile' in line:
                                profile = line.split(':')[1].strip()
                                profiles.append(profile)
                        
                        test.output = '\n'.join(profiles)
                        test.findings = [f"Found {len(profiles)} WiFi profiles"]
                        test.findings.extend(profiles[:10])
                        test.status = "COMPLETED"
                    except:
                        test.status = "ERROR"
                        test.reason = "Failed to enumerate WiFi profiles"
                else:
                    test.status = "SKIPPED"
                    test.reason = "Not applicable on this platform"
                    
            elif test.id == 'CA-004':
                if sys.platform == 'win32' and HAS_WINREG:
                    rdp_creds = []
                    
                    try:
                        key_path = r'Software\Microsoft\Terminal Server Client\Servers'
                        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)
                        
                        i = 0
                        while True:
                            try:
                                server_name = winreg.EnumKey(key, i)
                                rdp_creds.append(server_name)
                                i += 1
                            except WindowsError:
                                break
                        
                        winreg.CloseKey(key)
                        
                        test.output = '\n'.join(rdp_creds)
                        test.findings = [f"Found {len(rdp_creds)} RDP connection entries"]
                        test.findings.extend(rdp_creds[:10])
                        test.status = "COMPLETED"
                    except:
                        test.status = "COMPLETED"
                        test.findings = ["No RDP credential entries found"]
                else:
                    test.status = "SKIPPED"
                    test.reason = "Not applicable on this platform"
                    
        except Exception as e:
            test.status = "ERROR"
            test.reason = str(e)
            self.logger.log(f"Test {test.id} failed", error=str(e), status="ERROR", test_id=test.id)
    
    def execute_persistence_test(self, test):
        """Execute persistence tests"""
        try:
            if test.id == 'PS-001':
                startup_paths = []
                
                if sys.platform == 'win32':
                    startup_paths.append(os.path.join(os.getenv('APPDATA', ''), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'))
                    startup_paths.append(os.path.join(os.getenv('ALLUSERSPROFILE', ''), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'))
                
                findings = []
                for path in startup_paths:
                    if os.path.exists(path):
                        files = os.listdir(path)
                        findings.append(f"Startup folder: {path}")
                        findings.append(f"  Contains {len(files)} items")
                        for file in files[:5]:
                            findings.append(f"  - {file}")
                
                test.output = '\n'.join(findings)
                test.findings = findings if findings else ["No startup items found"]
                test.status = "COMPLETED"
                
            elif test.id == 'PS-002':
                services = self.tools.enumerate_services()
                suspicious = []
                
                suspicious_names = ['update', 'manager', 'service', 'system']
                for service in services:
                    name = service.get('name', '').lower()
                    if any(s in name for s in suspicious_names):
                        suspicious.append(service)
                
                test.output = json.dumps(suspicious[:20], indent=2)
                test.findings = [f"Analyzed {len(services)} services", f"Found {len(suspicious)} potentially suspicious services (manual review needed)"]
                test.status = "COMPLETED"
                
        except Exception as e:
            test.status = "ERROR"
            test.reason = str(e)
            self.logger.log(f"Test {test.id} failed", error=str(e), status="ERROR", test_id=test.id)
    
    def execute_network_test(self, test):
        """Execute network tests"""
        try:
            if test.id == 'NT-001':
                shares = self.tools.enumerate_shares()
                test.output = json.dumps(shares, indent=2)
                test.findings = [f"Found {len(shares)} network shares"]
                
                for share in shares:
                    test.findings.append(f"Share: {share.get('name')} -> {share.get('path')}")
                
                test.status = "COMPLETED"
                
            elif test.id == 'NT-002':
                open_ports = []
                
                if HAS_PSUTIL:
                    try:
                        connections = psutil.net_connections(kind='inet')
                        listening = [c for c in connections if c.status == 'LISTEN']
                        
                        for conn in listening:
                            open_ports.append({'port': conn.laddr.port, 'address': conn.laddr.ip})
                        
                        test.output = json.dumps(open_ports, indent=2)
                        test.findings = [f"Found {len(open_ports)} listening ports"]
                        
                        for port in open_ports[:20]:
                            test.findings.append(f"Port {port['port']} on {port['address']}")
                        
                        test.status = "COMPLETED"
                    except:
                        test.status = "ERROR"
                        test.reason = "Failed to enumerate ports"
                else:
                    test.status = "SKIPPED"
                    test.reason = "psutil library not available"
                    
        except Exception as e:
            test.status = "ERROR"
            test.reason = str(e)
            self.logger.log(f"Test {test.id} failed", error=str(e), status="ERROR", test_id=test.id)
    
    def execute_defense_evasion_test(self, test):
        """Execute defense evasion tests"""
        try:
            if test.id == 'DE-001':
                logging_config = self.tools.check_powershell_logging()
                test.output = json.dumps(logging_config, indent=2)
                
                if logging_config.get('script_block_logging'):
                    test.findings = ["WARNING: PowerShell Script Block Logging is ENABLED", "PowerShell activity will be logged"]
                else:
                    test.findings = ["PowerShell Script Block Logging is disabled", "PowerShell execution may not be fully logged"]
                
                test.status = "COMPLETED"
                
            elif test.id == 'DE-002':
                if sys.platform == 'win32':
                    try:
                        result = subprocess.run(['powershell', '-Command', 'Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, IoavProtectionEnabled, AntivirusEnabled | ConvertTo-Json'], capture_output=True, text=True, timeout=30)
                        
                        if result.returncode == 0:
                            defender_status = json.loads(result.stdout)
                            test.output = json.dumps(defender_status, indent=2)
                            
                            if defender_status.get('RealTimeProtectionEnabled'):
                                test.findings = ["WARNING: Windows Defender Real-Time Protection is ENABLED", "Malicious activities may be detected and blocked"]
                            else:
                                test.findings = ["Windows Defender Real-Time Protection is DISABLED", "System may be vulnerable to malware"]
                            
                            test.status = "COMPLETED"
                        else:
                            test.status = "ERROR"
                            test.reason = "Failed to query Windows Defender status"
                    except:
                        test.status = "ERROR"
                        test.reason = "PowerShell command failed"
                else:
                    test.status = "SKIPPED"
                    test.reason = "Not applicable on this platform"
                    
        except Exception as e:
            test.status = "ERROR"
            test.reason = str(e)
            self.logger.log(f"Test {test.id} failed", error=str(e), status="ERROR", test_id=test.id)
    
    def execute_advanced_host_test(self, test):
        """Execute advanced host tests"""
        try:
            if test.id == 'AH-001':
                software = []
                
                if sys.platform == 'win32':
                    try:
                        result = subprocess.run(['wmic', 'product', 'get', 'name,version', '/format:csv'], capture_output=True, text=True, timeout=120)
                        
                        lines = result.stdout.split('\n')[1:]
                        for line in lines:
                            if line.strip():
                                parts = line.split(',')
                                if len(parts) >= 3:
                                    software.append({'name': parts[1], 'version': parts[2]})
                        
                        test.output = json.dumps(software[:50], indent=2)
                        test.findings = [f"Found {len(software)} installed applications"]
                        
                        interesting = ['python', 'java', 'putty', 'winscp', 'vnc']
                        for sw in software:
                            name = sw.get('name', '').lower()
                            if any(i in name for i in interesting):
                                test.findings.append(f"Interesting: {sw.get('name')}")
                        
                        test.status = "COMPLETED"
                    except subprocess.TimeoutExpired:
                        test.status = "ERROR"
                        test.reason = "Command timed out"
                    except:
                        test.status = "ERROR"
                        test.reason = "Failed to enumerate software"
                else:
                    test.status = "SKIPPED"
                    test.reason = "Not applicable on this platform"
            
            elif test.id == 'AH-002':
                env_vars = dict(os.environ)
                sensitive_vars = {}
                sensitive_keys = ['path', 'home', 'user', 'temp', 'password', 'key', 'token']
                
                for key, value in env_vars.items():
                    if any(sk in key.lower() for sk in sensitive_keys):
                        sensitive_vars[key] = value
                
                test.output = json.dumps(sensitive_vars, indent=2)
                test.findings = [f"Found {len(sensitive_vars)} potentially sensitive environment variables"]
                
                for key in list(sensitive_vars.keys())[:10]:
                    test.findings.append(f"Variable: {key}")
                
                test.status = "COMPLETED"
            
            elif test.id == 'AH-003':
                if sys.platform == 'win32':
                    try:
                        import win32clipboard
                        
                        win32clipboard.OpenClipboard()
                        try:
                            clipboard_data = win32clipboard.GetClipboardData()
                            win32clipboard.CloseClipboard()
                            
                            if clipboard_data:
                                preview = clipboard_data[:100] if len(clipboard_data) > 100 else clipboard_data
                                test.output = f"Clipboard contains {len(clipboard_data)} characters"
                                test.findings = [f"Clipboard has content ({len(clipboard_data)} chars)", f"Preview: {preview}..."]
                            else:
                                test.findings = ["Clipboard is empty"]
                            
                            test.status = "COMPLETED"
                        except:
                            test.status = "COMPLETED"
                            test.findings = ["Clipboard is empty or inaccessible"]
                    except ImportError:
                        test.status = "SKIPPED"
                        test.reason = "win32clipboard not available"
                else:
                    test.status = "SKIPPED"
                    test.reason = "Not applicable on this platform"
                    
        except Exception as e:
            test.status = "ERROR"
            test.reason = str(e)
            self.logger.log(f"Test {test.id} failed", error=str(e), status="ERROR", test_id=test.id)
    
    def execute_filesystem_test(self, test):
        """Execute file system tests"""
        try:
            if test.id == 'FS-001':
                writable_dirs = []
                
                if sys.platform == 'win32':
                    check_dirs = ['C:\\Temp', 'C:\\Windows\\Temp', 'C:\\Windows\\Tasks', os.path.expandvars('%TEMP%')]
                else:
                    check_dirs = ['/tmp', '/var/tmp', '/dev/shm']
                
                for directory in check_dirs:
                    if os.path.exists(directory):
                        try:
                            test_file = os.path.join(directory, f'.test_{os.getpid()}')
                            with open(test_file, 'w') as f:
                                f.write('test')
                            os.remove(test_file)
                            writable_dirs.append(directory)
                        except:
                            pass
                
                test.output = '\n'.join(writable_dirs)
                test.findings = [f"Found {len(writable_dirs)} writable directories"]
                test.findings.extend(writable_dirs)
                test.status = "COMPLETED"
            
            elif test.id == 'FS-002':
                recent_files = []
                
                if sys.platform == 'win32':
                    recent_path = os.path.join(os.getenv('APPDATA', ''), 'Microsoft', 'Windows', 'Recent')
                    
                    if os.path.exists(recent_path):
                        try:
                            files = os.listdir(recent_path)
                            recent_files = files[:20]
                        except:
                            pass
                
                test.output = '\n'.join(recent_files)
                test.findings = [f"Found {len(recent_files)} recent file shortcuts"]
                test.findings.extend(recent_files[:10])
                test.status = "COMPLETED"
                
        except Exception as e:
            test.status = "ERROR"
            test.reason = str(e)
            self.logger.log(f"Test {test.id} failed", error=str(e), status="ERROR", test_id=test.id)
    
    def execute_test(self, test):
        """Execute a single test case"""
        self.logger.log(f"Executing test: {test.name}", status="INFO", test_id=test.id)
        
        if not test.can_run(self.config, self.is_admin):
            self.logger.log(f"Test skipped: {test.reason}", status="WARN", test_id=test.id)
            return test
        
        try:
            if test.id.startswith('HR-'):
                self.execute_host_recon_test(test)
            elif test.id.startswith('PE-'):
                self.execute_privesc_test(test)
            elif test.id.startswith('CA-'):
                self.execute_credential_test(test)
            elif test.id.startswith('PS-'):
                self.execute_persistence_test(test)
            elif test.id.startswith('NT-'):
                self.execute_network_test(test)
            elif test.id.startswith('DE-'):
                self.execute_defense_evasion_test(test)
            elif test.id.startswith('AH-'):
                self.execute_advanced_host_test(test)
            elif test.id.startswith('FS-'):
                self.execute_filesystem_test(test)
            else:
                test.status = "SKIPPED"
                test.reason = "Test category not implemented"
            
            self.results[test.category].append(test.to_dict())
            
            if test.status == "COMPLETED":
                self.logger.log(f"Test completed: {test.name}", status="SUCCESS", test_id=test.id)
            elif test.status == "ERROR":
                self.logger.log(f"Test failed: {test.name}", error=test.reason, status="ERROR", test_id=test.id)
                
        except Exception as e:
            test.status = "ERROR"
            test.reason = f"Unexpected error: {str(e)}"
            self.logger.log(f"Test exception: {test.name}", error=str(e), status="ERROR", test_id=test.id)
        
        return test
    
    def run_tests(self, tests):
        """Run all tests with threading"""
        self.logger.log(f"Starting test execution: {len(tests)} tests", status="INFO")
        
        filtered_tests = []
        for test in tests:
            if test.id in self.config.skip_tests:
                test.status = "SKIPPED"
                test.reason = "Excluded by configuration"
                self.test_results.append(test)
                continue
            
            if self.config.test_categories and test.category not in self.config.test_categories:
                test.status = "SKIPPED"
                test.reason = "Category not selected"
                self.test_results.append(test)
                continue
            
            filtered_tests.append(test)
        
        self.logger.log(f"Executing {len(filtered_tests)} tests (filtered from {len(tests)})", status="INFO")
        
        with ThreadPoolExecutor(max_workers=self.config.max_threads) as executor:
            futures = {executor.submit(self.execute_test, test): test for test in filtered_tests}
            
            for future in as_completed(futures):
                test = futures[future]
                try:
                    result = future.result()
                    self.test_results.append(result)
                except Exception as e:
                    self.logger.log(f"Test execution failed: {test.id}", error=str(e), status="ERROR")
                    test.status = "ERROR"
                    test.reason = str(e)
                    self.test_results.append(test)
        
        return self.test_results


class POCGenerator:
    """Generate working proof-of-concepts for discovered vulnerabilities"""
    
    def __init__(self, logger):
        self.logger = logger
    
    def generate_unquoted_service_poc(self, service_name, service_path):
        """Generate POC for unquoted service path exploitation"""
        poc = f"""
# Unquoted Service Path Exploitation POC
# Service: {service_name}
# Path: {service_path}

# Step 1: Identify injection point
# The service path has spaces without quotes, allowing path hijacking

# Step 2: Create malicious executable
# Place your payload at the injection point
# Example: If path is C:\\Program Files\\Vulnerable Service\\service.exe
# Place payload at C:\\Program.exe

# Step 3: Restart service to trigger
net stop "{service_name}"
net start "{service_name}"

# Your payload will execute with service privileges (typically SYSTEM)
"""
        return poc
    
    def generate_registry_persistence_poc(self, key_path, key_name):
        """Generate POC for registry persistence"""
        poc = f"""
# Registry Persistence POC
# Path: {key_path}
# Key: {key_name}

# Add persistence via Run key
reg add "{key_path}" /v "{key_name}" /t REG_SZ /d "C:\\path\\to\\payload.exe" /f

# Verify
reg query "{key_path}" /v "{key_name}"

# Payload will execute on user logon
"""
        return poc
    
    def generate_weak_permission_poc(self, target_path):
        """Generate POC for weak file permissions"""
        poc = f"""
# Weak Permission Exploitation POC
# Target: {target_path}

# Step 1: Verify permissions
icacls "{target_path}"

# Step 2: Backup original file
copy "{target_path}" "{target_path}.bak"

# Step 3: Replace with malicious file
copy "C:\\path\\to\\payload.exe" "{target_path}"

# Step 4: Trigger execution
# Depends on file type - may be service restart, system reboot, etc.
"""
        return poc
    
    def generate_pocs_for_findings(self, test_results):
        """Generate POCs for all exploitable findings"""
        pocs = []
        
        for test in test_results:
            if test.status != "COMPLETED":
                continue
            
            if test.id == 'PE-002' and test.findings:
                for finding in test.findings:
                    if 'Vulnerable:' in finding:
                        service_name = finding.replace('Vulnerable:', '').strip()
                        poc = self.generate_unquoted_service_poc(service_name, 'Unknown')
                        pocs.append({'test_id': test.id, 'type': 'Unquoted Service Path', 'target': service_name, 'poc': poc})
            
            elif test.id == 'PE-005' and test.findings:
                for finding in test.findings:
                    if 'HKCU\\' in finding or 'HKLM\\' in finding:
                        poc = self.generate_registry_persistence_poc(finding, 'Persistence')
                        pocs.append({'test_id': test.id, 'type': 'Registry Persistence', 'target': finding, 'poc': poc})
        
        return pocs


class EnhancedReporter:
    """Generate comprehensive reports with POCs"""
    
    def __init__(self, logger):
        self.logger = logger
    
    def generate_html_report(self, summary, pocs, output_file):
        """Generate HTML report"""
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Red Team Enumeration Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #c00; border-bottom: 3px solid #c00; padding-bottom: 10px; }}
        h2 {{ color: #333; border-bottom: 2px solid #ddd; padding-bottom: 5px; margin-top: 30px; }}
        .summary {{ background: #f9f9f9; padding: 15px; border-left: 4px solid #c00; margin: 20px 0; }}
        .test-case {{ background: #fff; border: 1px solid #ddd; padding: 15px; margin: 10px 0; }}
        .test-case.completed {{ border-left: 4px solid #0c0; }}
        .test-case.error {{ border-left: 4px solid #c00; }}
        .test-case.skipped {{ border-left: 4px solid #999; }}
        .findings {{ background: #f0f0f0; padding: 10px; margin: 10px 0; font-family: monospace; }}
        .poc {{ background: #1e1e1e; color: #0f0; padding: 15px; margin: 10px 0; font-family: monospace; white-space: pre-wrap; }}
        .status {{ display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 0.8em; font-weight: bold; }}
        .status.completed {{ background: #0c0; color: white; }}
        .status.error {{ background: #c00; color: white; }}
        .status.skipped {{ background: #999; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Red Team Enumeration Report</h1>
        <div class="summary">
            <h3>Scan Summary</h3>
            <p><strong>Target:</strong> {summary['scan_info']['target']}</p>
            <p><strong>User:</strong> {summary['scan_info']['user']}</p>
            <p><strong>Admin:</strong> {summary['scan_info']['is_admin']}</p>
            <p><strong>Duration:</strong> {summary['scan_info']['duration_seconds']} seconds</p>
            <p><strong>Tests Completed:</strong> {summary['test_summary']['completed']}</p>
            <p><strong>Tests Failed:</strong> {summary['test_summary']['error']}</p>
            <p><strong>Tests Skipped:</strong> {summary['test_summary']['skipped']}</p>
        </div>
        <h2>Test Results</h2>
"""
        
        for test in summary['all_tests']:
            status_class = test['status'].lower()
            html_content += f"""        <div class="test-case {status_class}">
            <h3>{test['id']}: {test['name']} <span class="status {status_class}">{test['status']}</span></h3>
            <p><strong>Category:</strong> {test['category']}</p>
            <p><strong>Description:</strong> {test['description']}#!/usr/bin/env python3
            <p><strong>Description:</strong> {test['description']}</p>
"""
            
            if test.get('reason'):
                html_content += f"            <p><strong>Reason:</strong> {test['reason']}</p>\n"
            
            if test.get('findings'):
                html_content += "            <div class='findings'><strong>Findings:</strong><br>\n"
                for finding in test['findings']:
                    html_content += f"                {finding}<br>\n"
                html_content += "            </div>\n"
            
            html_content += "        </div>\n"
        
        if pocs:
            html_content += "        <h2>Proof of Concepts</h2>\n"
            for poc in pocs:
                html_content += f"""        <div class="test-case">
            <h3>{poc['type']}</h3>
            <p><strong>Test:</strong> {poc['test_id']}</p>
            <p><strong>Target:</strong> {poc['target']}</p>
            <div class="poc">{poc['poc']}</div>
        </div>
"""
        
        html_content += """    </div>
</body>
</html>
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        self.logger.log(f"HTML report generated: {output_file}", status="SUCCESS")


class DomainEnumerator:
    """Main enumeration orchestrator"""
    
    def __init__(self, config):
        self.config = config
        self.logger = Logger(config.output_dir, config.verbose)
        self.executor = TestExecutor(config, self.logger)
        self.all_tests = []
    
    def load_all_tests(self):
        """Load all test cases"""
        self.logger.log("Loading test cases", status="INFO")
        
        self.all_tests.extend(HostReconTests.create_tests())
        self.all_tests.extend(PrivilegeEscalationTests.create_tests())
        self.all_tests.extend(CredentialAccessTests.create_tests())
        self.all_tests.extend(PersistenceTests.create_tests())
        self.all_tests.extend(NetworkTests.create_tests())
        self.all_tests.extend(DefenseEvasionTests.create_tests())
        self.all_tests.extend(AdvancedHostTests.create_tests())
        self.all_tests.extend(FileSystemTests.create_tests())
        
        self.logger.log(f"Loaded {len(self.all_tests)} test cases", status="SUCCESS")
        
        categories = {}
        for test in self.all_tests:
            categories[test.category] = categories.get(test.category, 0) + 1
        
        for category, count in categories.items():
            self.logger.log(f"  {category}: {count} tests", status="INFO")
    
    def run_enumeration(self):
        """Run the complete enumeration"""
        start_time = time.time()
        
        self.logger.log("="*80, status="INFO")
        self.logger.log("RED TEAM ENUMERATION TOOL - STARTING", status="INFO")
        self.logger.log("="*80, status="INFO")
        
        system_info = EmbeddedTools.get_system_info()
        self.logger.log(f"Target: {system_info.get('hostname', 'Unknown')}", status="INFO")
        self.logger.log(f"User: {system_info.get('username', 'Unknown')}", status="INFO")
        self.logger.log(f"Admin: {self.executor.is_admin}", status="INFO")
        
        self.load_all_tests()
        
        active_modules = [m for m, enabled in self.config.modules.items() if enabled]
        self.logger.log(f"Active modules: {', '.join(active_modules)}", status="INFO")
        
        self.logger.log("Starting test execution", status="INFO")
        test_results = self.executor.run_tests(self.all_tests)
        
        elapsed_time = time.time() - start_time
        
        summary = {
            'scan_info': {
                'start_time': datetime.fromtimestamp(start_time).isoformat(),
                'end_time': datetime.now().isoformat(),
                'duration_seconds': round(elapsed_time, 2),
                'target': system_info.get('hostname', 'Unknown'),
                'user': system_info.get('username', 'Unknown'),
                'is_admin': self.executor.is_admin
            },
            'test_summary': {
                'total': len(test_results),
                'completed': sum(1 for t in test_results if t.status == 'COMPLETED'),
                'error': sum(1 for t in test_results if t.status == 'ERROR'),
                'skipped': sum(1 for t in test_results if t.status == 'SKIPPED')
            },
            'results_by_category': self.executor.results,
            'all_tests': [t.to_dict() for t in test_results]
        }
        
        self.logger.save_results(summary)
        self.logger.save_testcase_report(test_results)
        
        self.logger.log("="*80, status="INFO")
        self.logger.log("ENUMERATION COMPLETE", status="SUCCESS")
        self.logger.log("="*80, status="INFO")
        self.logger.log(f"Duration: {elapsed_time:.2f} seconds", status="INFO")
        self.logger.log(f"Tests completed: {summary['test_summary']['completed']}", status="SUCCESS")
        self.logger.log(f"Tests failed: {summary['test_summary']['error']}", status="ERROR" if summary['test_summary']['error'] > 0 else "INFO")
        self.logger.log(f"Tests skipped: {summary['test_summary']['skipped']}", status="WARN")
        self.logger.log(f"Results saved to: {self.config.output_dir}", status="INFO")
        self.logger.log(f"Test case report: {self.logger.testcase_file}", status="INFO")
        
        self.print_high_value_findings(test_results)
        
        return summary
    
    def print_high_value_findings(self, test_results):
        """Print high-value findings"""
        self.logger.log("="*80, status="INFO")
        self.logger.log("HIGH-VALUE FINDINGS", status="CRITICAL")
        self.logger.log("="*80, status="INFO")
        
        high_value = []
        
        for test in test_results:
            if test.status == "COMPLETED" and test.findings:
                if any(keyword in ' '.join(test.findings).lower() for keyword in 
                       ['admin', 'password', 'credential', 'vulnerable', 'disabled', 'detected']):
                    high_value.append(test)
        
        if high_value:
            for test in high_value[:10]:
                self.logger.log(f"\n[{test.id}] {test.name}", status="WARN")
                for finding in test.findings[:5]:
                    self.logger.log(f"  └─ {finding}", status="INFO")
        else:
            self.logger.log("No high-value findings identified", status="INFO")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Advanced Domain Enumeration Tool - Red Team Edition (Fully Integrated)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Basic host enumeration
  python %(prog)s
  
  # Full enumeration with credentials
  python %(prog)s --domain example.com --username user --password pass
  
  # Specific modules only
  python %(prog)s --modules host_enum,privilege_escalation
  
  # Skip specific tests
  python %(prog)s --skip-tests HR-006,DE-002
  
  # Filter by category
  python %(prog)s --categories "Host Reconnaissance,Credential Access"
  
  # Generate POCs for findings
  python %(prog)s --generate-pocs
  
  # Generate HTML report
  python %(prog)s --html-report
  
  # Stealth mode with minimal threads
  python %(prog)s --stealth --threads 1
        '''
    )
    
    target_group = parser.add_argument_group('Target Options')
    target_group.add_argument('--domain', help='Target domain')
    target_group.add_argument('--dc', help='Domain controller IP/hostname')
    target_group.add_argument('--targets-file', help='File containing target hosts (one per line)')
    
    cred_group = parser.add_argument_group('Credential Options')
    cred_group.add_argument('--username', '-u', help='Username for authentication')
    cred_group.add_argument('--password', '-p', help='Password for authentication')
    cred_group.add_argument('--hash', help='NTLM hash for authentication')
    
    module_group = parser.add_argument_group('Module Options')
    module_group.add_argument('--modules', help='Comma-separated list of modules to run')
    module_group.add_argument('--skip-tests', help='Comma-separated list of test IDs to skip')
    module_group.add_argument('--categories', help='Comma-separated list of test categories to run')
    
    exec_group = parser.add_argument_group('Execution Options')
    exec_group.add_argument('--threads', '-t', type=int, default=5, help='Maximum number of threads (default: 5)')
    exec_group.add_argument('--timeout', type=int, default=300, help='Command timeout in seconds (default: 300)')
    exec_group.add_argument('--output', '-o', default='output', help='Output directory (default: output)')
    exec_group.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    exec_group.add_argument('--stealth', action='store_true', help='Stealth mode (slower, more cautious)')
    
    report_group = parser.add_argument_group('Reporting Options')
    report_group.add_argument('--generate-pocs', action='store_true', help='Generate proof-of-concept exploits')
    report_group.add_argument('--html-report', action='store_true', help='Generate HTML report')
    
    list_group = parser.add_argument_group('Information Options')
    list_group.add_argument('--list-modules', action='store_true', help='List available modules and exit')
    list_group.add_argument('--list-tests', action='store_true', help='List all test cases and exit')
    
    args = parser.parse_args()
    
    if args.list_modules:
        print("\nAvailable Modules:")
        print("=" * 60)
        modules = {
            'reconnaissance': 'External and internal reconnaissance',
            'host_enum': 'Host-level enumeration and system discovery',
            'privilege_escalation': 'Privilege escalation vulnerability checks',
            'credential_access': 'Credential harvesting and discovery',
            'lateral_movement': 'Lateral movement techniques (RISKY)',
            'domain_enum': 'Active Directory domain enumeration',
            'vulnerability_assessment': 'Vulnerability scanning and detection',
            'persistence_check': 'Persistence mechanism detection'
        }
        for module, desc in modules.items():
            print(f"  {module:30} - {desc}")
        print()
        return 0
    
    if args.list_tests:
        print("\nAvailable Test Cases:")
        print("=" * 80)
        
        config = Config()
        enumerator = DomainEnumerator(config)
        enumerator.load_all_tests()
        
        current_category = None
        for test in enumerator.all_tests:
            if test.category != current_category:
                current_category = test.category
                print(f"\n{current_category}:")
                print("-" * 80)
            
            admin_req = " [ADMIN REQUIRED]" if test.requires_admin else ""
            cred_req = " [CREDS REQUIRED]" if test.requires_creds else ""
            risk = f" [RISK: {test.risk_level}]"
            
            print(f"  {test.id:10} {test.name:40} {risk}{admin_req}{cred_req}")
            print(f"             {test.description}")
        
        print("\n" + "=" * 80)
        print(f"Total: {len(enumerator.all_tests)} test cases\n")
        return 0
    
    print("""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║  Advanced Domain Enumeration Tool - Red Team Edition             ║
    ║  Fully Integrated - No External Dependencies                     ║
    ║  For Authorized Security Testing Only                            ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """)
    
    config = Config()
    config.from_args(args)
    
    if config.stealth_mode:
        config.max_threads = 1
        config.timeout = 600
        print("[!] Stealth mode enabled - operations will be slower and more cautious")
    
    if not config.username and not config.password:
        print("[!] No credentials provided - some tests will be skipped")
    
    if config.modules.get('lateral_movement'):
        print("[!] WARNING: Lateral movement module is RISKY and may trigger alerts")
        response = input("[?] Continue? (yes/no): ")
        if response.lower() != 'yes':
            print("[!] Lateral movement disabled")
            config.modules['lateral_movement'] = False
    
    try:
        enumerator = DomainEnumerator(config)
        results = enumerator.run_enumeration()
        
        if args.generate_pocs:
            print("\n[*] Generating proof-of-concepts...")
            poc_generator = POCGenerator(enumerator.logger)
            pocs = poc_generator.generate_pocs_for_findings(enumerator.executor.test_results)
            
            if pocs:
                poc_file = os.path.join(config.output_dir, f'pocs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt')
                with open(poc_file, 'w', encoding='utf-8') as f:
                    f.write("="*80 + "\n")
                    f.write("PROOF OF CONCEPTS - DISCOVERED VULNERABILITIES\n")
                    f.write("="*80 + "\n\n")
                    
                    for poc in pocs:
                        f.write(f"\n{'='*80}\n")
                        f.write(f"Type: {poc['type']}\n")
                        f.write(f"Test: {poc['test_id']}\n")
                        f.write(f"Target: {poc['target']}\n")
                        f.write(f"{'='*80}\n")
                        f.write(poc['poc'])
                        f.write("\n\n")
                
                print(f"[+] Generated {len(pocs)} POCs: {poc_file}")
            else:
                print("[!] No exploitable vulnerabilities found for POC generation")
        
        if args.html_report:
            print("\n[*] Generating HTML report...")
            reporter = EnhancedReporter(enumerator.logger)
            html_file = os.path.join(config.output_dir, f'report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html')
            
            pocs = []
            if args.generate_pocs:
                poc_generator = POCGenerator(enumerator.logger)
                pocs = poc_generator.generate_pocs_for_findings(enumerator.executor.test_results)
            
            reporter.generate_html_report(results, pocs, html_file)
            print(f"[+] HTML report generated: {html_file}")
        
        return 0
        
    except KeyboardInterrupt:
        print("\n[!] Enumeration interrupted by user")
        return 1
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
