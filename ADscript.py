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
from typing import List, Dict, Any, Optional

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False

# =======================================================================================
# Logger and Console Output Handler
# =======================================================================================

class Logger:
    """Central logging and output handler"""
    
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
    
    def log(self, message, status='INFO', error=None, test_id=None, thread_id=None):
        """Log message with severity and context"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = {
            'timestamp': timestamp,
            'status': status,
            'message': message,
            'error': str(error) if error else None,
            'test_id': test_id,
            'thread_id': thread_id
        }
        
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
                f.write(f"{timestamp} [{status}]")
                if test_id:
                    f.write(f" [TC:{test_id}]")
                if thread_id:
                    f.write(f" [T:{thread_id}]")
                f.write(f" {message}\n")
                if error:
                    f.write(f"  Error: {error}\n")
    
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
                    # Support both dict-like objects and plain dicts
                    if hasattr(tc, '__dict__') and not isinstance(tc, dict):
                        tc_dict = {
                            'id': getattr(tc, 'id', ''),
                            'category': getattr(tc, 'category', ''),
                            'name': getattr(tc, 'name', ''),
                            'status': getattr(tc, 'status', ''),
                            'description': getattr(tc, 'description', ''),
                            'reason': getattr(tc, 'reason', None),
                            'output': getattr(tc, 'output', None),
                            'findings': getattr(tc, 'findings', []) or [],
                        }
                    else:
                        tc_dict = tc

                    f.write(f"Test Case ID: {tc_dict.get('id','')}")
                    f.write("\n")
                    f.write(f"Category: {tc_dict.get('category','')}")
                    f.write("\n")
                    f.write(f"Name: {tc_dict.get('name','')}")
                    f.write("\n")
                    f.write(f"Status: {tc_dict.get('status','')}")
                    f.write("\n")
                    f.write(f"Description: {tc_dict.get('description','')}")
                    f.write("\n")

                    reason = tc_dict.get('reason')
                    if reason:
                        f.write(f"Reason: {reason}")
                        f.write("\n")

                    output = tc_dict.get('output')
                    if output:
                        f.write("Output Snippet:\n")
                        if isinstance(output, str) and len(output) > 500:
                            output_snip = output[:500] + "..."
                        else:
                            output_snip = output
                        f.write(f"  {output_snip}")
                        f.write("\n")

                    findings = tc_dict.get('findings') or []
                    if findings:
                        f.write("Findings:\n")
                        for finding in findings:
                            f.write(f"  - {finding}")
                            f.write("\n")

                    f.write("-"*80 + "\n\n")


class TestCase:
    """Base class for test cases"""
    def __init__(self, test_id, name, category, description, requires_creds=False, 
                 risk_level='MEDIUM', requires_admin=False, windows_only=True):
        self.id = test_id
        self.name = name
        self.category = category
        self.description = description
        self.requires_creds = requires_creds
        self.risk_level = risk_level
        self.requires_admin = requires_admin
        self.windows_only = windows_only
        
        self.status = "PENDING"
        self.reason = None
        self.output = None
        self.findings = []
        self.error = None
        self.duration = 0.0
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'category': self.category,
            'description': self.description,
            'requires_creds': self.requires_creds,
            'risk_level': self.risk_level,
            'requires_admin': self.requires_admin,
            'windows_only': self.windows_only,
            'status': self.status,
            'reason': self.reason,
            'output': self.output,
            'findings': self.findings,
            'error': self.error,
            'duration': self.duration
        }

# =======================================================================================
# Configuration Handling
# =======================================================================================

class Config:
    """Configuration handler for the enumeration tool"""
    
    def __init__(self, args):
        """Load configuration from command line args"""
        self.domain = args.domain
        self.dc = args.dc
        self.targets_file = args.targets_file
        
        self.username = args.username
        self.password = args.password
        self.hash = args.hash
        
        self.modules = []
        if args.modules:
            self.modules = [m.strip().lower() for m in args.modules.split(',')]
        
        self.skip_tests = []
        if args.skip_tests:
            self.skip_tests = [t.strip().upper() for t in args.skip_tests.split(',')]
        
        self.categories = []
        if args.categories:
            self.categories = [c.strip() for c in args.categories.split(',')]
        
        self.max_threads = args.threads
        self.timeout = args.timeout
        self.output_dir = args.output
        self.verbose = args.verbose
        self.stealth_mode = args.stealth
        self.generate_pocs = args.generate_pocs
        self.html_report = args.html_report
        
        os.makedirs(self.output_dir, exist_ok=True)
    
    def to_dict(self):
        """Convert config to dictionary"""
        return {
            'domain': self.domain,
            'dc': self.dc,
            'targets_file': self.targets_file,
            'username': self.username,
            'password': '***' if self.password else None,
            'hash': self.hash,
            'modules': self.modules,
            'skip_tests': self.skip_tests,
            'categories': self.categories,
            'max_threads': self.max_threads,
            'timeout': self.timeout,
            'output_dir': self.output_dir,
            'verbose': self.verbose,
            'stealth_mode': self.stealth_mode,
            'generate_pocs': self.generate_pocs,
            'html_report': self.html_report
        }

# =======================================================================================
# Tool Runner for Subprocess and System Commands
# =======================================================================================

class ToolRunner:
    """Unified wrapper for subprocess execution and system queries"""
    
    def __init__(self, logger: Logger, config: Config):
        self.logger = logger
        self.config = config
    
    def run_command(self, cmd, timeout=None, shell=False, ignore_errors=False):
        """Run a system command and capture output"""
        if timeout is None:
            timeout = self.config.timeout
        
        try:
            if self.config.verbose:
                self.logger.log(f"Executing command: {cmd}", status="INFO")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=shell
            )
            
            stdout = result.stdout.strip()
            stderr = result.stderr.strip()
            returncode = result.returncode
            
            if returncode != 0 and not ignore_errors:
                self.logger.log(
                    f"Command failed (exit code {returncode}): {cmd}",
                    status="WARN",
                    error=stderr or f"Exit code: {returncode}"
                )
            
            return stdout, stderr, returncode
        
        except subprocess.TimeoutExpired as e:
            self.logger.log(
                f"Command timed out: {cmd}", 
                status="WARN",
                error=str(e)
            )
            return None, "Timeout", -1
        except Exception as e:
            self.logger.log(
                f"Error running command: {cmd}",
                status="ERROR",
                error=str(e)
            )
            return None, str(e), -1
    
    # ----------------------------------------------------------
    # System Information and Host Recon Tools
    # ----------------------------------------------------------
    
    def get_system_info(self):
        """Get basic system information"""
        if sys.platform == 'win32':
            cmd = ['systeminfo']
            stdout, stderr, code = self.run_command(cmd)
            return stdout or stderr
        else:
            cmds = [['uname', '-a'], ['hostnamectl'], ['cat', '/etc/os-release']]
            outputs = []
            for cmd in cmds:
                stdout, stderr, _ = self.run_command(cmd, ignore_errors=True)
                if stdout:
                    outputs.append(stdout)
            return "\n\n".join(outputs)
    
    def enumerate_users(self):
        """Enumerate local users"""
        if sys.platform == 'win32':
            cmd = ['net', 'user']
        else:
            cmd = ['cut', '-d:', '-f1', '/etc/passwd']
        stdout, stderr, _ = self.run_command(cmd)
        return stdout
    
    def enumerate_groups(self):
        """Enumerate local groups"""
        if sys.platform == 'win32':
            cmd = ['net', 'localgroup']
        else:
            cmd = ['cut', '-d:', '-f1', '/etc/group']
        stdout, stderr, _ = self.run_command(cmd)
        return stdout
    
    def enumerate_processes(self):
        """Enumerate running processes"""
        if sys.platform == 'win32':
            cmd = ['tasklist', '/v']
        else:
            cmd = ['ps', 'aux']
        stdout, stderr, _ = self.run_command(cmd, timeout=60)
        
        processes = []
        for line in stdout.splitlines()[1:]:
            if not line.strip():
                continue
            processes.append({'raw': line})
        return processes
    
    def enumerate_network_interfaces(self):
        """Enumerate network interfaces"""
        if sys.platform == 'win32':
            cmd = ['ipconfig', '/all']
        else:
            cmd = ['ip', 'address']
        stdout, stderr, _ = self.run_command(cmd)
        return stdout.splitlines()
    
    def enumerate_services(self):
        """Enumerate services"""
        if sys.platform == 'win32':
            cmd = ['sc', 'query', 'type=', 'service', 'state=', 'all']
        else:
            cmd = ['systemctl', 'list-units', '--type=service', '--all']
        stdout, stderr, _ = self.run_command(cmd, timeout=60)
        return stdout.splitlines()
    
    # ----------------------------------------------------------
    # Windows-specific Security Tools
    # ----------------------------------------------------------
    
    def check_admin_privileges(self):
        """Determine if current process has administrative privileges"""
        if sys.platform == 'win32':
            try:
                stdout, _, _ = self.run_command(['whoami', '/groups'])
                if 'S-1-5-32-544' in stdout or 'BUILTIN\\Administrators' in stdout:
                    return True
                return False
            except Exception:
                return False
        else:
            try:
                return os.geteuid() == 0
            except AttributeError:
                return False
    
    def detect_av_edr(self):
        """Detect antivirus and EDR products"""
        products = []
        
        if sys.platform == 'win32':
            # Windows Security Center WMI queries
            wmi_cmds = [
                ['powershell', '-NoProfile', '-Command',
                 "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | "
                 "Select-Object -ExpandProperty displayName"],
                ['powershell', '-NoProfile', '-Command',
                 "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiSpywareProduct | "
                 "Select-Object -ExpandProperty displayName"]
            ]
            
            for cmd in wmi_cmds:
                stdout, _, _ = self.run_command(cmd, ignore_errors=True)
                if stdout:
                    for line in stdout.splitlines():
                        if line.strip() and line.strip() not in products:
                            products.append(line.strip())
            
            # Process-based detection for common EDRs
            edr_keywords = [
                'carbonblack', 'crowdstrike', 'falcon', 'kaspersky',
                'cylance', 'defender', 'mcafee', 'symantec',
                'sentinel', 'splunk', 'tanium', 'qualys'
            ]
            
            ps_cmd = ['tasklist', '/v', '/fo', 'csv']
            stdout, _, _ = self.run_command(ps_cmd, ignore_errors=True)
            
            for line in stdout.splitlines():
                lower = line.lower()
                for keyword in edr_keywords:
                    if keyword in lower:
                        if line.strip() not in products:
                            products.append(f"Process-based detection: {line.strip()}")
        
        else:
            # On Linux, check for common agents
            edr_processes = [
                'falcon-sensor', 'cbagent', 'qualys', 'auditbeat',
                'filebeat', 'ossec', 'wazuh', 'symcfgd', 'savscand'
            ]
            stdout, _, _ = self.run_command(['ps', 'aux'], ignore_errors=True)
            for line in stdout.splitlines():
                for proc in edr_processes:
                    if proc.lower() in line.lower():
                        products.append(line.strip())
        
        return products
    
    def get_uac_settings(self):
        """Get UAC configuration from registry (Windows)"""
        if sys.platform != 'win32' or not HAS_WINREG:
            return None
        
        try:
            key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            
            settings = {}
            values = [
                'EnableLUA',
                'ConsentPromptBehaviorAdmin',
                'ConsentPromptBehaviorUser',
                'PromptOnSecureDesktop'
            ]
            
            for value in values:
                try:
                    data, regtype = winreg.QueryValueEx(key, value)
                    settings[value] = data
                except FileNotFoundError:
                    settings[value] = None
            
            winreg.CloseKey(key)
            return settings
        except Exception as e:
            self.logger.log(
                "Failed to read UAC configuration",
                status="ERROR",
                error=str(e)
            )
            return None
    
    def enumerate_scheduled_tasks(self):
        """Enumerate scheduled tasks"""
        if sys.platform == 'win32':
            cmd = ['schtasks', '/query', '/fo', 'LIST', '/v']
        else:
            cmd = ['crontab', '-l']
        stdout, _, _ = self.run_command(cmd, timeout=60, ignore_errors=True)
        return stdout.splitlines()
    
    def enumerate_autoruns(self):
        """Enumerate autorun registry keys and startup locations"""
        autoruns = []
        
        if sys.platform == 'win32' and HAS_WINREG:
            run_paths = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
            ]
            
            for path in run_paths:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
                    i = 0
                    while True:
                        try:
                            name, value, regtype = winreg.EnumValue(key, i)
                            autoruns.append({
                                'key': path,
                                'name': name,
                                'value': value
                            })
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except FileNotFoundError:
                    continue
        
        return autoruns

# =======================================================================================
# Test Case Definitions
# =======================================================================================

class HostReconTests:
    """Host reconnaissance test cases"""
    
    @staticmethod
    def create_tests():
        tests = []
        tests.append(TestCase(
            'HR-001', 'System Information Enumeration', 'Host Reconnaissance',
            'Collect OS version, hostname, and basic system information', risk_level='LOW'
        ))
        tests.append(TestCase(
            'HR-002', 'Local User Enumeration', 'Host Reconnaissance',
            'Enumerate local user accounts on the system', risk_level='MEDIUM'
        ))
        tests.append(TestCase(
            'HR-003', 'Local Group Enumeration', 'Host Reconnaissance',
            'Enumerate local groups and their members', risk_level='MEDIUM'
        ))
        tests.append(TestCase(
            'HR-004', 'Administrative Privilege Check', 'Host Reconnaissance',
            'Check if current context has administrative privileges', risk_level='HIGH'
        ))
        tests.append(TestCase(
            'HR-005', 'Running Process Enumeration', 'Host Reconnaissance',
            'Enumerate running processes and identify high-value targets', risk_level='HIGH'
        ))
        tests.append(TestCase(
            'HR-006', 'Security Product Detection', 'Host Reconnaissance',
            'Detect installed AV and EDR products on the endpoint', risk_level='MEDIUM'
        ))
        tests.append(TestCase(
            'HR-007', 'Network Interface Enumeration', 'Host Reconnaissance',
            'Enumerate network interfaces and IP configurations', risk_level='LOW'
        ))
        tests.append(TestCase(
            'HR-008', 'Windows Service Enumeration', 'Host Reconnaissance',
            'Enumerate Windows services and configurations', risk_level='MEDIUM'
        ))
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
                             'Enumerate startup folders for persistence mechanisms', risk_level='LOW'))
        tests.append(TestCase('PS-002', 'Service-Based Persistence Detection', 'Persistence',
                             'Identify services that might be used for persistence', risk_level='MEDIUM'))
        return tests


class NetworkTests:
    """Network enumeration test cases"""
    
    @staticmethod
    def create_tests():
        tests = []
        tests.append(TestCase('NT-001', 'Network Share Enumeration', 'Network Reconnaissance',
                             'Enumerate accessible network shares', risk_level='MEDIUM'))
        tests.append(TestCase('NT-002', 'Local Port Enumeration', 'Network Reconnaissance',
                             'Enumerate listening network ports', risk_level='MEDIUM'))
        return tests


class DefenseEvasionTests:
    """Defense evasion assessment test cases"""
    
    @staticmethod
    def create_tests():
        tests = []
        tests.append(TestCase('DE-001', 'PowerShell Logging Configuration', 'Defense Evasion',
                             'Check PowerShell logging and script block logging configuration', risk_level='MEDIUM'))
        tests.append(TestCase('DE-002', 'Security Event Log Configuration', 'Defense Evasion',
                             'Assess security event log configuration and log size', risk_level='LOW'))
        return tests


class DiscoveryTests:
    """Discovery test cases"""
    
    @staticmethod
    def create_tests():
        tests = []
        tests.append(TestCase('DS-001', 'Domain Trust Discovery', 'Discovery',
                             'Discover domain trusts (if applicable)', risk_level='MEDIUM', requires_creds=True))
        tests.append(TestCase('DS-002', 'Local Admin Account Discovery', 'Discovery',
                             'Discover local administrators and high-value accounts', risk_level='HIGH'))
        return tests


class AccessHygieneTests:
    """Access hygiene assessment test cases"""
    
    @staticmethod
    def create_tests():
        tests = []
        tests.append(TestCase('AH-001', 'Password Policy Assessment', 'Access Hygiene',
                             'Assess local password policy settings', risk_level='MEDIUM'))
        tests.append(TestCase('AH-002', 'Environment Variable Enumeration', 'Access Hygiene',
                             'Enumerate environment variables for secrets', risk_level='MEDIUM'))
        tests.append(TestCase('AH-003', 'Clipboard Content Check', 'Access Hygiene',
                             'Check clipboard content for sensitive data', risk_level='LOW'))
        return tests


class FileSystemTests:
    """File system assessment test cases"""
    
    @staticmethod
    def create_tests():
        tests = []
        tests.append(TestCase('FS-001', 'World-Writable Directory Discovery', 'File System',
                             'Identify world-writable directories', risk_level='MEDIUM'))
        tests.append(TestCase('FS-002', 'Recent Files Analysis', 'File System',
                             'Analyze recent files for sensitive information', risk_level='MEDIUM'))
        return tests

# =======================================================================================
# POC (Proof-of-Concept) Generation
# =======================================================================================

class POCGenerator:
    """Generate POC descriptions for specific findings"""
    
    def __init__(self, logger: Logger, config: Config):
        self.logger = logger
        self.config = config
    
    def generate_for_test(self, test: TestCase) -> List[str]:
        """Generate POCs for a specific test"""
        pocs = []
        
        # NOTE: These are high-level descriptive POCs, not exploit code execution.
        
        if test.id == 'PE-002' and test.findings:
            pocs.append(
                "Unquoted Service Path POC:\n"
                "- Identify the vulnerable service path from the findings.\n"
                "- Determine if you can write to the parent directory.\n"
                "- Place a binary with the same name as the first path segment.\n"
                "- Restart the service and observe if your binary is executed.\n"
                "WARNING: Only perform this in a controlled, authorized test environment."
            )
        
        if test.id == 'AH-002' and test.findings:
            pocs.append(
                "Environment Variable Abuse POC:\n"
                "- From the enumerated variables, identify any containing secrets, tokens, or credentials.\n"
                "- Demonstrate impact by showing access to restricted services using these values.\n"
                "WARNING: Do not exfiltrate or disclose real secrets outside the test scope."
            )
        
        if test.id == 'HR-006' and test.findings:
            pocs.append(
                "AV/EDR Evasion Assessment POC (DESCRIPTIVE ONLY):\n"
                "- For each detected security product, document which telemetry it collects.\n"
                "- Plan test cases to validate detection coverage (e.g., script execution, file drops).\n"
                "- Coordinate with defenders to review which actions were or were not detected during testing."
            )
        
        return pocs

# =======================================================================================
# HTML Report Generator
# =======================================================================================

class HTMLReportGenerator:
    """Generate HTML report from enumeration results"""
    
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def generate(self, summary: Dict[str, Any], testcases: List[TestCase], pocs: Dict[str, List[str]] = None) -> str:
        html_file = os.path.join(self.output_dir, "report.html")
        
        status_badge = {
            'COMPLETED': '#4CAF50',
            'ERROR': '#F44336',
            'SKIPPED': '#9E9E9E',
            'PENDING': '#FFC107'
        }
        
        html_content = []
        html_content.append("<!DOCTYPE html>")
        html_content.append("<html lang=\"en\">")
        html_content.append("<head>")
        html_content.append("<meta charset=\"UTF-8\">")
        html_content.append("<title>Red Team Enumeration Report</title>")
        html_content.append("<style>")
        html_content.append("""
body { font-family: Arial, sans-serif; background-color: #121212; color: #e0e0e0; }
.container { width: 95%; max-width: 1200px; margin: 20px auto; background: #1e1e1e; padding: 20px; border-radius: 8px; }
.section { margin-bottom: 30px; }
.section h2 { border-bottom: 2px solid #424242; padding-bottom: 5px; color: #90CAF9; }
.summary-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }
.summary-item { background: #263238; padding: 10px; border-radius: 4px; }
.badge { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 0.8em; margin-left: 10px; }
.badge-status { color: #fff; }
.table { width: 100%; border-collapse: collapse; margin-top: 10px; }
.table th, .table td { padding: 8px; border-bottom: 1px solid #424242; vertical-align: top; }
.table th { background: #263238; color: #90CAF9; }
.testcase { margin-bottom: 15px; padding: 10px; background: #212121; border-radius: 4px; }
.findings { margin-top: 5px; padding-left: 20px; }
.poc-block { margin-top: 10px; padding: 10px; background: #263238; border-left: 4px solid #FFB300; }
.small { font-size: 0.85em; color: #b0bec5; }
""")
        html_content.append("</style>")
        html_content.append("</head>")
        html_content.append("<body>")
        html_content.append("<div class=\"container\">")
        html_content.append("<h1>Red Team Enumeration Report</h1>")
        
        # Summary section
        html_content.append("<div class=\"section\">")
        html_content.append("<h2>Summary</h2>")
        html_content.append("<div class=\"summary-grid\">")
        
        summary_items = [
            ("Target", summary.get('target', 'N/A')),
            ("Domain", summary.get('domain', 'N/A')),
            ("User", summary.get('user', 'N/A')),
            ("Has Admin", str(summary.get('is_admin', False))),
            ("Total Tests", str(summary.get('total_tests', 0))),
            ("Completed", str(summary.get('completed', 0))),
            ("Failed", str(summary.get('failed', 0))),
            ("Skipped", str(summary.get('skipped', 0))),
            ("Duration", f"{summary.get('duration', 0):.2f} seconds"),
        ]
        
        for label, value in summary_items:
            html_content.append("<div class=\"summary-item\">")
            html_content.append(f"<strong>{label}:</strong><br>{value}")
            html_content.append("</div>")
        
        html_content.append("</div>")
        html_content.append("</div>")
        
        # Test cases section
        html_content.append("<div class=\"section\">")
        html_content.append("<h2>Test Cases</h2>")
        
        html_content.append("<table class=\"table\">")
        html_content.append("<tr><th>ID</th><th>Name</th><th>Category</th><th>Status</th><th>Description</th><th>Findings</th></tr>")
        
        for tc in testcases:
            status_color = status_badge.get(tc.status, '#757575')
            findings_html = ""
            if tc.findings:
                findings_html = "<ul class=\"findings\">" + "".join([f"<li>{f}</li>" for f in tc.findings]) + "</ul>"
            
            html_content.append("<tr>")
            html_content.append(f"<td>{tc.id}</td>")
            html_content.append(f"<td>{tc.name}</td>")
            html_content.append(f"<td>{tc.category}</td>")
            html_content.append(f"<td><span class=\"badge badge-status\" style=\"background:{status_color}\">{tc.status}</span></td>")
            html_content.append(f"<td>{tc.description}</td>")
            html_content.append(f"<td>{findings_html}</td>")
            html_content.append("</tr>")
        
        html_content.append("</table>")
        html_content.append("</div>")
        
        # POC section (if any)
        if pocs:
            html_content.append("<div class=\"section\">")
            html_content.append("<h2>POC Recommendations</h2>")
            
            for test_id, poc_list in pocs.items():
                if not poc_list:
                    continue
                html_content.append("<div class=\"poc-block\">")
                html_content.append(f"<strong>{test_id}</strong><br>")
                for poc in poc_list:
                    html_content.append(f"<p class=\"small\">{poc}</p>")
                html_content.append("</div>")
            
            html_content.append("</div>")
        
        html_content.append("</div></body></html>")
        
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(html_content))
        
        return html_file

# =======================================================================================
# Main Enumeration Engine
# =======================================================================================

class DomainEnumerator:
    """Main orchestrator for red team enumeration"""
    
    def __init__(self, config: Config, logger: Logger):
        self.config = config
        self.logger = logger
        self.tools = ToolRunner(logger, config)
        self.poc_gen = POCGenerator(logger, config)
        
        self.tests: List[TestCase] = []
        self.results: Dict[str, Any] = {}
        
        self.is_admin = self.tools.check_admin_privileges()
        self.platform = sys.platform
    
    def initialize_tests(self):
        """Initialize all test cases based on configuration"""
        all_tests = []
        
        # Host Recon
        host_tests = HostReconTests.create_tests()
        all_tests.extend(host_tests)
        
        # Privilege Escalation
        pe_tests = PrivilegeEscalationTests.create_tests()
        all_tests.extend(pe_tests)
        
        # Credential Access
        cred_tests = CredentialAccessTests.create_tests()
        all_tests.extend(cred_tests)
        
        # Persistence
        pers_tests = PersistenceTests.create_tests()
        all_tests.extend(pers_tests)
        
        # Network
        net_tests = NetworkTests.create_tests()
        all_tests.extend(net_tests)
        
        # Defense Evasion
        de_tests = DefenseEvasionTests.create_tests()
        all_tests.extend(de_tests)
        
        # Discovery
        disc_tests = DiscoveryTests.create_tests()
        all_tests.extend(disc_tests)
        
        # Access Hygiene
        ah_tests = AccessHygieneTests.create_tests()
        all_tests.extend(ah_tests)
        
        # File System
        fs_tests = FileSystemTests.create_tests()
        all_tests.extend(fs_tests)
        
        # Apply filters
        selected_tests = []
        
        for test in all_tests:
            if self.config.modules:
                module_map = {
                    'host': 'Host Reconnaissance',
                    'priv_esc': 'Privilege Escalation',
                    'creds': 'Credential Access',
                    'persistence': 'Persistence',
                    'network': 'Network Reconnaissance',
                    'defense': 'Defense Evasion',
                    'discovery': 'Discovery',
                    'access': 'Access Hygiene',
                    'filesystem': 'File System'
                }
                
                allowed_categories = []
                for mod in self.config.modules:
                    if mod in module_map:
                        allowed_categories.append(module_map[mod])
                
                if allowed_categories and test.category not in allowed_categories:
                    continue
            
            if self.config.categories and test.category not in self.config.categories:
                continue
            
            if test.id in self.config.skip_tests:
                continue
            
            if test.windows_only and sys.platform != 'win32':
                test.status = "SKIPPED"
                test.reason = "Windows-specific test on non-Windows platform"
                selected_tests.append(test)
                continue
            
            if test.requires_admin and not self.is_admin:
                test.status = "SKIPPED"
                test.reason = "Requires administrative privileges"
                selected_tests.append(test)
                continue
            
            if test.requires_creds and not (self.config.username and (self.config.password or self.config.hash)):
                test.status = "SKIPPED"
                test.reason = "Requires credentials (username/password or hash)"
                selected_tests.append(test)
                continue
            
            selected_tests.append(test)
        
        self.tests = selected_tests
        return selected_tests
    
    def execute_test(self, test: TestCase, thread_id: int = None):
        """Execute individual test case"""
        start_time = datetime.now()
        self.logger.log(f"Executing test: {test.name}", status="INFO", test_id=test.id, thread_id=thread_id)
        
        try:
            # Host Recon
            if test.id == 'HR-001':
                output = self.tools.get_system_info()
                test.output = output
                if output:
                    lines = output.splitlines()
                    test.findings = [line for line in lines[:20] if line.strip()]
                test.status = "COMPLETED"
            
            elif test.id == 'HR-002':
                output = self.tools.enumerate_users()
                test.output = output
                if output:
                    users = [line.strip() for line in output.splitlines() if line.strip()]
                    test.findings = users[:20]
                test.status = "COMPLETED"
            
            elif test.id == 'HR-003':
                output = self.tools.enumerate_groups()
                test.output = output
                if output:
                    groups = [line.strip() for line in output.splitlines() if line.strip()]
                    test.findings = groups[:20]
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
                    name = proc.get('raw', '')
                    for p in interesting:
                        if p.lower() in name.lower():
                            test.findings.append(f"Interesting process: {name}")
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
                    if isinstance(iface, str):
                        test.findings.append(iface)
            
            elif test.id == 'HR-008':
                services = self.tools.enumerate_services()
                test.output = "\n".join(services[:100])
                test.findings = [f"Found {len(services)} services"]
            
            # Privilege Escalation
            elif test.id == 'PE-001':
                services = self.tools.enumerate_services()
                potential = [s for s in services if 'manual' in s.lower() or 'auto' in s.lower()]
                test.output = "\n".join(potential[:100])
                test.findings = [f"Found {len(potential)} candidate services for permission review"]
                test.status = "COMPLETED"
            
            elif test.id == 'PE-002':
                services = self.tools.enumerate_services()
                vulnerable = []
                for s in services:
                    if '"' not in s and ' ' in s and 'exe' in s.lower():
                        vulnerable.append(s)
                test.output = "\n".join(vulnerable[:50])
                test.findings = [f"Found {len(vulnerable)} potential unquoted service paths"]
                test.status = "COMPLETED"
            
            elif test.id == 'PE-003':
                settings = self.tools.get_uac_settings()
                if settings is None:
                    test.status = "SKIPPED"
                    test.reason = "Unable to read UAC settings"
                else:
                    test.output = json.dumps(settings, indent=2)
                    enable_lua = settings.get('EnableLUA', 0)
                    consent_admin = settings.get('ConsentPromptBehaviorAdmin', 0)
                    prompt_secure = settings.get('PromptOnSecureDesktop', 0)
                    
                    if enable_lua == 0:
                        test.findings.append("WARNING: UAC is disabled (EnableLUA=0)")
                    else:
                        test.findings.append(f"UAC is enabled (EnableLUA={enable_lua})")
                    
                    test.findings.append(f"ConsentPromptBehaviorAdmin={consent_admin}")
                    test.findings.append(f"PromptOnSecureDesktop={prompt_secure}")
                    
                    test.status = "COMPLETED"
            
            elif test.id == 'PE-004':
                tasks = self.tools.enumerate_scheduled_tasks()
                test.output = "\n".join(tasks[:200])
                test.findings = [f"Found {len(tasks)} scheduled tasks (detailed review required)"]
                test.status = "COMPLETED"
            
            elif test.id == 'PE-005':
                autoruns = self.tools.enumerate_autoruns()
                test.output = json.dumps(autoruns[:50], indent=2)
                test.findings = [f"Found {len(autoruns)} autorun entries"]
                test.status = "COMPLETED"
            
            # Credential Access
            elif test.id == 'CA-001':
                sensitive_patterns = ['password', 'credential', 'secret', 'keyfile']
                search_paths = []
                
                if sys.platform == 'win32':
                    userprofile = os.environ.get('USERPROFILE', '')
                    search_paths = [
                        os.path.join(userprofile, 'Documents'),
                        os.path.join(userprofile, 'Desktop'),
                        os.path.join(userprofile, 'Downloads')
                    ]
                else:
                    home = os.path.expanduser('~')
                    search_paths = [home]
                
                matches = []
                for path in search_paths:
                    if not os.path.isdir(path):
                        continue
                    try:
                        for root, dirs, files in os.walk(path):
                            for f in files:
                                lower = f.lower()
                                for pat in sensitive_patterns:
                                    if pat in lower:
                                        matches.append(os.path.join(root, f))
                    except Exception:
                        continue
                
                test.output = "\n".join(matches[:100])
                test.findings = [f"Found {len(matches)} files with potentially sensitive names"]
                test.status = "COMPLETED"
            
            elif test.id == 'CA-002':
                locations = []
                if sys.platform == 'win32':
                    userprofile = os.environ.get('USERPROFILE', '')
                    locations.extend([
                        os.path.join(userprofile, 'AppData', 'Roaming', 'Mozilla', 'Firefox'),
                        os.path.join(userprofile, 'AppData', 'Local', 'Google', 'Chrome'),
                        os.path.join(userprofile, 'AppData', 'Local', 'Microsoft', 'Edge')
                    ])
                else:
                    home = os.path.expanduser('~')
                    locations.extend([
                        os.path.join(home, '.mozilla', 'firefox'),
                        os.path.join(home, '.config', 'google-chrome'),
                        os.path.join(home, '.config', 'chromium')
                    ])
                
                existing = [loc for loc in locations if os.path.exists(loc)]
                test.output = "\n".join(existing)
                test.findings = [f"Detected browser credential locations: {len(existing)}"]
                test.status = "COMPLETED"
            
            elif test.id == 'CA-003':
                if sys.platform == 'win32':
                    try:
                        result = subprocess.run(
                            ['netsh', 'wlan', 'show', 'profiles'],
                            capture_output=True,
                            text=True,
                            timeout=30
                        )
                        
                        profiles = []
                        for line in result.stdout.split('\n'):
                            if 'All User Profile' in line:
                                parts = line.split(':', 1)
                                if len(parts) == 2:
                                    profile = parts[1].strip()
                                    profiles.append(profile)
                        
                        test.output = '\n'.join(profiles)
                        test.findings = [f"Found {len(profiles)} WiFi profiles"]
                        test.findings.extend(profiles[:10])
                        test.status = "COMPLETED"
                    except Exception:
                        test.status = "ERROR"
                        test.reason = "Failed to enumerate WiFi profiles"
                else:
                    test.status = "SKIPPED"
                    test.reason = "Not applicable on this platform"
            
            elif test.id == 'CA-004':
                if sys.platform == 'win32' and HAS_WINREG:
                    rdp_creds = []
                    try:
                        key_path = r"Software\Microsoft\Terminal Server Client\Servers"
                        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)
                        i = 0
                        while True:
                            try:
                                server_name = winreg.EnumKey(key, i)
                                rdp_creds.append(server_name)
                                i += 1
                            except OSError:
                                break
                        winreg.CloseKey(key)
                    except Exception:
                        pass
                    
                    test.output = "\n".join(rdp_creds)
                    test.findings = [f"Found {len(rdp_creds)} RDP saved servers"]
                    test.status = "COMPLETED"
                else:
                    test.status = "SKIPPED"
                    test.reason = "Not applicable or winreg not available"
            
            # Persistence
            elif test.id == 'PS-001':
                paths = []
                if sys.platform == 'win32':
                    userprofile = os.environ.get('USERPROFILE', '')
                    paths.append(os.path.join(userprofile, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'))
                    paths.append(os.path.join(userprofile, 'AppData', 'Local', 'Microsoft', 'Windows', 'Shell', 'Startup'))
                else:
                    home = os.path.expanduser('~')
                    paths.append(os.path.join(home, '.config', 'autostart'))
                
                entries = []
                for path in paths:
                    if os.path.isdir(path):
                        try:
                            for f in os.listdir(path):
                                entries.append(os.path.join(path, f))
                        except Exception:
                            continue
                
                test.output = "\n".join(entries)
                test.findings = [f"Found {len(entries)} startup items"]
                test.status = "COMPLETED"
            
            elif test.id == 'PS-002':
                services = self.tools.enumerate_services()
                potential = []
                for s in services:
                    lower = s.lower()
                    if 'automatic' in lower or 'auto' in lower:
                        potential.append(s)
                test.output = "\n".join(potential[:100])
                test.findings = [f"Found {len(potential)} services that might be used for persistence"]
                test.status = "COMPLETED"
            
            # Network
            elif test.id == 'NT-001':
                if sys.platform == 'win32':
                    cmd = ['net', 'view']
                else:
                    cmd = ['smbclient', '-L', 'localhost', '-N']
                stdout, _, _ = self.tools.run_command(cmd, ignore_errors=True)
                test.output = stdout
                test.findings = [f"Output size: {len(stdout.splitlines())} lines"]
                test.status = "COMPLETED"
            
            elif test.id == 'NT-002':
                if sys.platform == 'win32':
                    cmd = ['netstat', '-ano']
                else:
                    cmd = ['ss', '-tulnp']
                stdout, _, _ = self.tools.run_command(cmd, timeout=60, ignore_errors=True)
                test.output = stdout
                lines = stdout.splitlines()
                test.findings = [f"Found {max(0, len(lines)-1)} listening entries (approx)."]
                test.status = "COMPLETED"
            
            # Defense Evasion
            elif test.id == 'DE-001':
                if sys.platform == 'win32':
                    ps_cmd = [
                        'powershell', '-NoProfile', '-Command',
                        "Get-ItemProperty -Path HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging"
                    ]
                    stdout, _, _ = self.tools.run_command(ps_cmd, ignore_errors=True)
                    test.output = stdout
                    if 'EnableScriptBlockLogging' in stdout:
                        test.findings.append("Script Block Logging key present (review value).")
                    else:
                        test.findings.append("Script Block Logging not explicitly configured.")
                    test.status = "COMPLETED"
                else:
                    test.status = "SKIPPED"
                    test.reason = "Windows-specific test"
            
            elif test.id == 'DE-002':
                if sys.platform == 'win32':
                    ps_cmd = [
                        'powershell', '-NoProfile', '-Command',
                        "Get-EventLog -LogName Security -Newest 5 | Select-Object -Property Index,TimeGenerated,EventID"
                    ]
                    stdout, _, _ = self.tools.run_command(ps_cmd, ignore_errors=True)
                    test.output = stdout
                    lines = stdout.splitlines()
                    test.findings = [f"Sample of last {len(lines)} security events collected."]
                    test.status = "COMPLETED"
                else:
                    test.status = "SKIPPED"
                    test.reason = "Windows-specific test"
            
            # Discovery
            elif test.id == 'DS-001':
                if sys.platform == 'win32':
                    cmd = ['nltest', '/domain_trusts']
                    stdout, _, _ = self.tools.run_command(cmd, ignore_errors=True)
                    test.output = stdout
                    test.findings = [f"Domain trust entries: {len(stdout.splitlines())} (review required)"]
                    test.status = "COMPLETED"
                else:
                    test.status = "SKIPPED"
                    test.reason = "Windows-specific test"
            
            elif test.id == 'DS-002':
                if sys.platform == 'win32':
                    cmd = ['net', 'localgroup', 'Administrators']
                    stdout, _, _ = self.tools.run_command(cmd, ignore_errors=True)
                    test.output = stdout
                    admins = [l.strip() for l in stdout.splitlines() if l.strip()]
                    test.findings = [f"Local administrators (approx): {len(admins)}"]
                    test.status = "COMPLETED"
                else:
                    test.status = "SKIPPED"
                    test.reason = "Windows-specific test"
            
            # Access Hygiene
            elif test.id == 'AH-001':
                if sys.platform == 'win32':
                    cmd = ['net', 'accounts']
                    stdout, _, _ = self.tools.run_command(cmd, ignore_errors=True)
                    test.output = stdout
                    for line in stdout.splitlines():
                        if 'Minimum password length' in line:
                            test.findings.append(line.strip())
                        if 'Password expires' in line:
                            test.findings.append(line.strip())
                    test.status = "COMPLETED"
                else:
                    test.status = "SKIPPED"
                    test.reason = "Windows-specific test"
            
            elif test.id == 'AH-002':
                env_vars = os.environ
                test.output = json.dumps(dict(env_vars), indent=2)
                interesting = []
                for k, v in env_vars.items():
                    if any(x in k.lower() for x in ['password', 'secret', 'token', 'key']):
                        interesting.append(f"{k}={v}")
                test.findings = [f"Found {len(interesting)} potentially sensitive environment variables"]
                test.findings.extend(interesting[:10])
                test.status = "COMPLETED"
            
            elif test.id == 'AH-003':
                try:
                    if sys.platform == 'win32':
                        cmd = ['powershell', '-NoProfile', '-Command',
                               "Get-Clipboard -Raw"]
                        stdout, _, _ = self.tools.run_command(cmd, ignore_errors=True)
                        if stdout.strip():
                            test.output = stdout[:500]
                            test.findings.append("Clipboard contains data (content truncated).")
                        else:
                            test.findings.append("Clipboard appears empty.")
                        test.status = "COMPLETED"
                    else:
                        test.status = "SKIPPED"
                        test.reason = "Clipboard check implementation not present for this platform"
                except Exception:
                    test.status = "ERROR"
                    test.reason = "Failed to query clipboard"
            
            # File System
            elif test.id == 'FS-001':
                paths = []
                if sys.platform == 'win32':
                    paths = [os.environ.get('SystemDrive', 'C:') + '\\']
                else:
                    paths = ['/tmp', '/var/tmp', '/dev/shm']
                
                writable = []
                for path in paths:
                    if os.path.isdir(path):
                        try:
                            test_file = os.path.join(path, f"writable_test_{os.getpid()}")
                            with open(test_file, 'w') as f:
                                f.write("test")
                            os.remove(test_file)
                            writable.append(path)
                        except Exception:
                            continue
                
                test.output = "\n".join(writable)
                test.findings = [f"World-writable or current-user-writable directories: {len(writable)}"]
                test.status = "COMPLETED"
            
            elif test.id == 'FS-002':
                if sys.platform == 'win32':
                    userprofile = os.environ.get('USERPROFILE', '')
                    docs = os.path.join(userprofile, 'Documents')
                    paths = [docs]
                else:
                    home = os.path.expanduser('~')
                    paths = [home]
                
                recent_files = []
                for path in paths:
                    if os.path.isdir(path):
                        try:
                            for root, dirs, files in os.walk(path):
                                for f in files:
                                    full = os.path.join(root, f)
                                    try:
                                        mtime = os.path.getmtime(full)
                                        recent_files.append((full, mtime))
                                    except Exception:
                                        continue
                        except Exception:
                            continue
                
                recent_files.sort(key=lambda x: x[1], reverse=True)
                display = [f"{f[0]}" for f in recent_files[:50]]
                test.output = "\n".join(display)
                test.findings = [f"Collected {len(display)} most recent files in target directories"]
                test.status = "COMPLETED"
            
            else:
                test.status = "SKIPPED"
                test.reason = "No implementation for this test ID"
        
        except Exception as e:
            test.status = "ERROR"
            test.reason = str(e)
            test.error = str(e)
            self.logger.log(
                f"Error executing test: {test.name}",
                status="ERROR",
                error=str(e),
                test_id=test.id,
                thread_id=thread_id
            )
        
        end_time = datetime.now()
        test.duration = (end_time - start_time).total_seconds()
        
        if test.status == "COMPLETED":
            self.logger.log(
                f"Test completed: {test.name}",
                status="SUCCESS",
                test_id=test.id,
                thread_id=thread_id
            )
        elif test.status == "SKIPPED":
            self.logger.log(
                f"Test skipped: {test.name} ({test.reason})",
                status="WARN",
                test_id=test.id,
                thread_id=thread_id
            )
    
    def run_enumeration(self):
        """Run all enumeration tests"""
        self.logger.log("="*78, status="INFO")
        self.logger.log("RED TEAM ENUMERATION TOOL - STARTING", status="INFO")
        self.logger.log("="*78, status="INFO")
        
        if not (self.config.username and (self.config.password or self.config.hash)):
            self.logger.log(
                "No credentials provided - some tests will be skipped",
                status="WARN"
            )
        
        tests = self.initialize_tests()
        
        self.logger.log(
            f"Executing {len(tests)} tests (filtered from {len(tests)})",
            status="INFO"
        )
        
        results_queue = queue.Queue()
        
        def worker(tests_to_run, thread_id):
            for test in tests_to_run:
                if self.config.stealth_mode:
                    import time
                    time.sleep(1.0)
                self.execute_test(test, thread_id=thread_id)
                results_queue.put(test)
        
        if self.config.max_threads <= 1 or self.config.stealth_mode:
            worker(tests, 1)
        else:
            threads = []
            chunk_size = max(1, len(tests) // self.config.max_threads)
            for i in range(self.config.max_threads):
                start = i * chunk_size
                end = (i + 1) * chunk_size if i < self.config.max_threads - 1 else len(tests)
                if start >= len(tests):
                    break
                t = threading.Thread(
                    target=worker,
                    args=(tests[start:end], i+1),
                    daemon=True
                )
                threads.append(t)
                t.start()
            
            for t in threads:
                t.join()
        
        test_results = list(self.tests)
        self.logger.save_testcase_report(test_results)
        
        summary = {
            'target': self.config.dc or self.config.domain or self.config.targets_file or os.environ.get('COMPUTERNAME'),
            'domain': self.config.domain,
            'user': os.environ.get('USERNAME') or os.environ.get('USER'),
            'is_admin': self.is_admin,
            'platform': self.platform,
            'total_tests': len(test_results),
            'completed': sum(1 for t in test_results if t.status == "COMPLETED"),
            'failed': sum(1 for t in test_results if t.status == "ERROR"),
            'skipped': sum(1 for t in test_results if t.status == "SKIPPED"),
            'duration': sum(t.duration for t in test_results),
            'config': self.config.to_dict()
        }
        
        all_tests_dict = [t.to_dict() for t in test_results]
        
        results = {
            'summary': summary,
            'tests': all_tests_dict
        }
        
        if self.config.generate_pocs:
            poc_map = {}
            for t in test_results:
                pocs = self.poc_gen.generate_for_test(t)
                if pocs:
                    poc_map[t.id] = pocs
            results['pocs'] = poc_map
        
        self.results = results
        self.logger.save_results(results)
        
        if self.config.html_report:
            poc_map = results.get('pocs', {})
            html_gen = HTMLReportGenerator(self.config.output_dir)
            html_file = html_gen.generate(summary, test_results, poc_map)
            self.logger.log(
                f"HTML report generated: {html_file}",
                status="INFO"
            )
        
        return results

# =======================================================================================
# Argument Parsing and Main Entry Point
# =======================================================================================

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Advanced Domain Enumeration Tool - Red Team Edition (Fully Integrated)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python redteamscanner.py --domain corp.local --dc dc01.corp.local --username user --password pass
  python redteamscanner.py --modules host,network,priv_esc --html-report
  python redteamscanner.py --categories "Host Reconnaissance,Privilege Escalation" --generate-pocs
"""
    )
    
    parser.add_argument("--domain", help="Domain name to target (e.g., corp.local)")
    parser.add_argument("--dc", help="Domain controller hostname or IP")
    parser.add_argument("--targets-file", help="File containing list of target hosts")
    
    parser.add_argument("--username", help="Username for authentication")
    parser.add_argument("--password", help="Password for authentication")
    parser.add_argument("--hash", help="NTLM hash for authentication")
    
    parser.add_argument(
        "--modules",
        help="Comma-separated list of modules to run "
             "(host,priv_esc,creds,persistence,network,defense,discovery,access,filesystem)"
    )
    parser.add_argument(
        "--skip-tests",
        help="Comma-separated list of test IDs to skip (e.g., HR-006,PE-003)"
    )
    parser.add_argument(
        "--categories",
        help="Comma-separated list of test categories to run "
             "(e.g., 'Host Reconnaissance,Privilege Escalation')"
    )
    
    parser.add_argument(
        "--threads", "-t", type=int, default=5,
        help="Maximum number of threads (default: 5)"
    )
    parser.add_argument(
        "--timeout", type=int, default=300,
        help="Command timeout in seconds (default: 300)"
    )
    parser.add_argument(
        "--output", "-o", default="output",
        help="Output directory (default: output)"
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Enable verbose logging"
    )
    parser.add_argument(
        "--stealth", action="store_true",
        help="Enable stealth mode (reduced concurrency, delays between tests)"
    )
    parser.add_argument(
        "--generate-pocs", action="store_true",
        help="Generate proof-of-concept descriptions for applicable findings"
    )
    parser.add_argument(
        "--html-report", action="store_true",
        help="Generate HTML report"
    )
    parser.add_argument(
        "--list-modules", action="store_true",
        help="List available modules and exit"
    )
    parser.add_argument(
        "--list-tests", action="store_true",
        help="List all test cases and exit"
    )
    
    return parser.parse_args()


def list_modules():
    print("Available modules:")
    print("  host         - Host Reconnaissance")
    print("  priv_esc     - Privilege Escalation")
    print("  creds        - Credential Access")
    print("  persistence  - Persistence")
    print("  network      - Network Reconnaissance")
    print("  defense      - Defense Evasion")
    print("  discovery    - Discovery")
    print("  access       - Access Hygiene")
    print("  filesystem   - File System")


def list_tests():
    dummy_logger = Logger(output_dir='output', verbose=False)
    dummy_config = Config(argparse.Namespace(
        domain=None, dc=None, targets_file=None,
        username=None, password=None, hash=None,
        modules=None, skip_tests=None, categories=None,
        threads=1, timeout=300, output='output',
        verbose=False, stealth=False, generate_pocs=False,
        html_report=False, list_modules=False, list_tests=False
    ))
    enumerator = DomainEnumerator(dummy_config, dummy_logger)
    tests = enumerator.initialize_tests()
    
    print("Available test cases:")
    for t in tests:
        print(f"  {t.id:6} {t.category:25} {t.name}")


def main():
    args = parse_arguments()
    
    if args.list_modules:
        list_modules()
        return 0
    
    if args.list_tests:
        list_tests()
        return 0
    
    config = Config(args)
    logger = Logger(output_dir=config.output_dir, verbose=config.verbose)
    
    print("""
    ╔═══════════════════════════════════════════════════════════════════╗
    ║  Advanced Domain Enumeration Tool - Red Team Edition             ║
    ║  Fully Integrated - No External Dependencies                     ║
    ║  For Authorized Security Testing Only                            ║
    ╚═══════════════════════════════════════════════════════════════════╝
    """)
    
    enumerator = DomainEnumerator(config, logger)
    results = enumerator.run_enumeration()
    
    summary = results.get('summary', {})
    logger.log("="*78, status="INFO")
    logger.log("ENUMERATION COMPLETE", status="SUCCESS")
    logger.log("="*78, status="INFO")
    logger.log(f"Duration: {summary.get('duration', 0):.2f} seconds", status="INFO")
    logger.log(f"Tests completed: {summary.get('completed', 0)}", status="SUCCESS")
    logger.log(f"Tests failed: {summary.get('failed', 0)}", status="INFO")
    logger.log(f"Tests skipped: {summary.get('skipped', 0)}", status="WARN")
    logger.log(f"Results saved to: {config.output_dir}", status="INFO")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
