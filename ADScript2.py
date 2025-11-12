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

class ToolIntegration:
    """Manages external tool execution, embedding features directly if flag is set"""
    def __init__(self, logger, temp_dir, use_embedded_tools=False):
        self.logger = logger
        self.temp_dir = temp_dir
        self.use_embedded_tools = use_embedded_tools  # Flag to use embedded tools
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

        # Embedding the tool scripts as Python strings
        self.embedded_tools = {
            'powerview': self._embed_powerview(),
            'sharphound': self._embed_sharphound(),
            'adrecon': self._embed_adrecon(),
            'invoke-aclpwn': self._embed_aclpwn(),
            'powerupsql': self._embed_powerupsql()
        }
    
    def _embed_powerview(self):
        return """
        # Embed PowerView functionality directly here
        # Example PowerShell code from PowerView for domain enumeration
        Function Get-DomainUser {
            Get-ADUser -Filter * -Property * | Select-Object SamAccountName, Enabled, LastLogonDate, PasswordLastSet
        }
        # Add the required PowerView functions here, like Get-DomainComputer, Get-DomainGroup, etc.
        """
    
    def _embed_sharphound(self):
        return """
        # Embed SharpHound functionality directly here
        # Example PowerShell script for SharpHound BloodHound data collection
        Function Invoke-BloodHound {
            # Collection logic goes here
            Write-Host "BloodHound collection started"
        }
        """
    
    def _embed_adrecon(self):
        return """
        # Embed ADRecon functionality directly here
        # Example PowerShell code for ADRecon data gathering
        Function Invoke-ADRecon {
            Write-Host "ADRecon data collection started"
        }
        """
    
    def _embed_aclpwn(self):
        return """
        # Embed Invoke-ACLPwn functionality directly here
        # Example PowerShell code for ACL Pwn attack path finding
        Function Find-InterestingDomainAcl {
            Write-Host "Finding interesting ACLs"
        }
        """
    
    def _embed_powerupsql(self):
        return """
        # Embed PowerUpSQL functionality directly here
        # Example PowerShell code for SQL enumeration
        Function Get-SQLInstanceDomain {
            Write-Host "Finding SQL instances"
        }
        """
    
    def download_tool(self, tool_name):
        """Download tool from GitHub if use_embedded_tools is False"""
        if self.use_embedded_tools:
            self.logger.log(f"Using embedded {tool_name} tool.", status="INFO")
            return True
        
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
    
    def get_tool_script(self, tool_name):
        """Retrieve the embedded script for a tool"""
        if self.use_embedded_tools and tool_name in self.embedded_tools:
            return self.embedded_tools[tool_name]
        return None
        

# Integrating the tools into the enumeration class

class DomainEnumerator:
    def __init__(self, config):
        self.config = config
        self.logger = Logger()
        self.temp_dir = tempfile.mkdtemp(prefix='domain_enum_')
        self.tool_integration = ToolIntegration(self.logger, self.temp_dir, use_embedded_tools=config.use_embedded_tools)
        
    def run_command(self, command, shell=False, powershell=False, timeout=300, thread_id=""):
        """Execute command and return output"""
        try:
            if powershell:
                script = self.tool_integration.get_tool_script('powerview')  # Use embedded PowerView if flag is set
                if script:
                    command = script  # Replace command with embedded script
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

def main():
    parser = argparse.ArgumentParser(
        description='Advanced Domain Enumeration Tool - Red Team Edition',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--fine-I-will-do-it-myself', action='store_true',
                       help='Use embedded tool scripts instead of downloading them')
    
    args = parser.parse_args()
    
    # Create config and set the flag based on input
    config = Config()
    config.use_embedded_tools = args.fine_I_will_do_it_myself
    
    # Run the enumeration
    enumerator = DomainEnumerator(config)
    enumerator.run_enumeration()

if __name__ == "__main__":
    main()
