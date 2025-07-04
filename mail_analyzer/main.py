# Mail Header Analyzer - Standalone Application
# A comprehensive tool for analyzing email headers, authentication, and delivery paths

import sys
import os
import re
import json
import threading
import time
import socket
import subprocess
from datetime import datetime
from email import message_from_string
from email.utils import parsedate_to_datetime, parseaddr
from pathlib import Path

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QTabWidget, QGroupBox, QLineEdit, QPushButton, QLabel, QTextEdit, 
    QComboBox, QCheckBox, QTreeWidget, QTreeWidgetItem, QFileDialog, 
    QMessageBox, QSplitter, QProgressBar, QMenuBar, QAction, QStatusBar
)
from PyQt5.QtCore import Qt, QObject, pyqtSignal, QThread, QTimer
from PyQt5.QtGui import QFont, QIcon


class Logger(QObject):
    """Simple logger for the application"""
    message_logged = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.debug_mode = False
    
    def set_debug_mode(self, enabled):
        self.debug_mode = enabled
    
    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted_message = f"[{timestamp}] [{level}] {message}"
        self.message_logged.emit(formatted_message)
    
    def debug(self, message):
        if self.debug_mode:
            self.log(message, "DEBUG")
    
    def info(self, message):
        self.log(message, "INFO")
    
    def warning(self, message):
        self.log(message, "WARNING")
    
    def error(self, message):
        self.log(message, "ERROR")
    
    def success(self, message):
        self.log(message, "SUCCESS")


class MailAnalysisTools(QObject):
    """Core mail analysis functionality"""
    result_ready = pyqtSignal(str, str)  # result, level
    analysis_ready = pyqtSignal(dict, str)  # analysis_data, analysis_type
    
    def __init__(self, logger):
        super().__init__()
        self.logger = logger
        
    def analyze_headers(self, headers_text):
        """Analyze email headers comprehensively"""
        def _analyze():
            try:
                self.logger.debug("Starting email header analysis")
                self.result_ready.emit("Analyzing email headers...", "INFO")
                
                # Parse headers using email library
                msg = message_from_string(headers_text)
                
                analysis_data = {
                    'headers': {},
                    'summary': '',
                    'analysis': '',
                    'delivery_path': {}
                }
                
                # Extract all headers
                for header, value in msg.items():
                    analysis_data['headers'][header] = value
                
                # Generate summary
                summary = self._generate_summary(msg)
                analysis_data['summary'] = summary
                
                # Generate detailed analysis
                detailed_analysis = self._generate_detailed_analysis(msg, headers_text)
                analysis_data['analysis'] = detailed_analysis
                
                # Analyze delivery path
                delivery_path = self._analyze_delivery_path(headers_text)
                analysis_data['delivery_path'] = delivery_path
                
                self.result_ready.emit("✅ Header analysis completed", "SUCCESS")
                self.analysis_ready.emit(analysis_data, "headers")
                
            except Exception as e:
                self.result_ready.emit(f"Header analysis error: {str(e)}", "ERROR")
                
        thread = threading.Thread(target=_analyze)
        thread.daemon = True
        thread.start()
    
    def _generate_summary(self, msg):
        """Generate a quick summary of email headers"""
        summary_parts = []
        
        # Basic email info
        from_addr = msg.get('From', 'Unknown')
        to_addr = msg.get('To', 'Unknown')
        subject = msg.get('Subject', 'No Subject')
        date = msg.get('Date', 'Unknown')
        
        summary_parts.append(f"📧 Email Summary:")
        summary_parts.append(f"From: {from_addr}")
        summary_parts.append(f"To: {to_addr}")
        summary_parts.append(f"Subject: {subject}")
        summary_parts.append(f"Date: {date}")
        summary_parts.append("")
        
        # Authentication status
        auth_results = msg.get('Authentication-Results', '')
        if auth_results:
            spf_status = "UNKNOWN"
            dkim_status = "UNKNOWN"
            dmarc_status = "UNKNOWN"
            
            if 'spf=pass' in auth_results.lower():
                spf_status = "✅ PASS"
            elif 'spf=fail' in auth_results.lower():
                spf_status = "❌ FAIL"
            elif 'spf=softfail' in auth_results.lower():
                spf_status = "⚠️ SOFTFAIL"
            
            if 'dkim=pass' in auth_results.lower():
                dkim_status = "✅ PASS"
            elif 'dkim=fail' in auth_results.lower():
                dkim_status = "❌ FAIL"
            
            if 'dmarc=pass' in auth_results.lower():
                dmarc_status = "✅ PASS"
            elif 'dmarc=fail' in auth_results.lower():
                dmarc_status = "❌ FAIL"
            
            summary_parts.append(f"🔐 Authentication Status:")
            summary_parts.append(f"SPF: {spf_status}")
            summary_parts.append(f"DKIM: {dkim_status}")
            summary_parts.append(f"DMARC: {dmarc_status}")
            summary_parts.append("")
        
        # Count received headers (hops)
        received_headers = msg.get_all('Received') or []
        hop_count = len(received_headers)
        summary_parts.append(f"🛤️ Delivery Path: {hop_count} hops")
        
        # Check for suspicious indicators
        suspicious_indicators = []
        
        # Check for suspicious sender domains
        sender_name, sender_email = parseaddr(from_addr)
        if sender_email:
            sender_domain = sender_email.split('@')[-1] if '@' in sender_email else ''
            
            # Check for suspicious patterns
            if any(suspicious in sender_domain.lower() for suspicious in ['temp', 'disposable', 'guerrilla']):
                suspicious_indicators.append("Temporary/disposable sender domain")
        
        # Check for missing security headers
        if not msg.get('DKIM-Signature'):
            suspicious_indicators.append("Missing DKIM signature")
        
        if not auth_results:
            suspicious_indicators.append("Missing authentication results")
        
        # Check for unusual routing
        if hop_count > 10:
            suspicious_indicators.append(f"Unusual number of hops ({hop_count})")
        
        if suspicious_indicators:
            summary_parts.append(f"⚠️ Potential Issues:")
            for indicator in suspicious_indicators:
                summary_parts.append(f"  • {indicator}")
        else:
            summary_parts.append(f"✅ No obvious security issues detected")
        
        return "\n".join(summary_parts)
    
    def _generate_detailed_analysis(self, msg, headers_text):
        """Generate detailed header analysis"""
        analysis_parts = []
        
        analysis_parts.append("🔍 DETAILED HEADER ANALYSIS")
        analysis_parts.append("=" * 50)
        analysis_parts.append("")
        
        # Message ID analysis
        message_id = msg.get('Message-ID', '')
        if message_id:
            analysis_parts.append(f"📨 Message ID Analysis:")
            analysis_parts.append(f"  ID: {message_id}")
            
            # Extract domain from Message-ID
            id_match = re.search(r'@([^>]+)', message_id)
            if id_match:
                id_domain = id_match.group(1)
                analysis_parts.append(f"  Originating server: {id_domain}")
            analysis_parts.append("")
        
        # Return-Path analysis
        return_path = msg.get('Return-Path', '')
        if return_path:
            analysis_parts.append(f"↩️ Return Path Analysis:")
            analysis_parts.append(f"  Path: {return_path}")
            
            # Check if Return-Path matches From
            from_addr = msg.get('From', '')
            if return_path and from_addr:
                return_email = re.search(r'<([^>]+)>', return_path)
                from_email = re.search(r'<([^>]+)>', from_addr)
                
                if return_email and from_email:
                    if return_email.group(1) != from_email.group(1):
                        analysis_parts.append(f"  ⚠️ Return-Path differs from From address")
                    else:
                        analysis_parts.append(f"  ✅ Return-Path matches From address")
            analysis_parts.append("")
        
        # DKIM analysis
        dkim_signature = msg.get('DKIM-Signature', '')
        if dkim_signature:
            analysis_parts.append(f"🔑 DKIM Signature Analysis:")
            
            # Extract DKIM parameters
            dkim_params = {}
            for param in dkim_signature.split(';'):
                param = param.strip()
                if '=' in param:
                    key, value = param.split('=', 1)
                    dkim_params[key.strip()] = value.strip()
            
            if 'v' in dkim_params:
                analysis_parts.append(f"  Version: {dkim_params['v']}")
            if 'a' in dkim_params:
                analysis_parts.append(f"  Algorithm: {dkim_params['a']}")
            if 'd' in dkim_params:
                analysis_parts.append(f"  Domain: {dkim_params['d']}")
            if 's' in dkim_params:
                analysis_parts.append(f"  Selector: {dkim_params['s']}")
            
            analysis_parts.append("")
        
        # Received headers analysis
        received_headers = msg.get_all('Received') or []
        if received_headers:
            analysis_parts.append(f"🛤️ Delivery Path Analysis ({len(received_headers)} hops):")
            
            total_delay = 0
            prev_timestamp = None
            
            for i, received in enumerate(reversed(received_headers)):  # Start from oldest
                analysis_parts.append(f"  Hop {i+1}:")
                
                # Extract timestamp
                timestamp_match = re.search(r';(.+)$', received.replace('\n', ' '))
                if timestamp_match:
                    timestamp_str = timestamp_match.group(1).strip()
                    try:
                        timestamp = parsedate_to_datetime(timestamp_str)
                        analysis_parts.append(f"    Time: {timestamp}")
                        
                        if prev_timestamp:
                            delay = (timestamp - prev_timestamp).total_seconds()
                            total_delay += delay
                            if delay > 0:
                                analysis_parts.append(f"    Delay: {delay:.1f} seconds")
                        
                        prev_timestamp = timestamp
                    except:
                        analysis_parts.append(f"    Time: {timestamp_str} (parsing failed)")
                
                # Extract servers
                server_match = re.search(r'from\s+([^\s]+)', received)
                if server_match:
                    server = server_match.group(1)
                    analysis_parts.append(f"    Server: {server}")
                
                # Extract IP addresses
                ip_matches = re.findall(r'\[(\d+\.\d+\.\d+\.\d+)\]', received)
                for ip in ip_matches:
                    analysis_parts.append(f"    IP: {ip}")
                
                analysis_parts.append("")
            
            if total_delay > 0:
                analysis_parts.append(f"  📊 Total delivery time: {total_delay:.1f} seconds")
                if total_delay > 300:  # 5 minutes
                    analysis_parts.append(f"  ⚠️ Slow delivery detected")
                analysis_parts.append("")
        
        # Content-Type analysis
        content_type = msg.get('Content-Type', '')
        if content_type:
            analysis_parts.append(f"📄 Content Analysis:")
            analysis_parts.append(f"  Type: {content_type}")
            
            if 'multipart' in content_type.lower():
                analysis_parts.append(f"  📎 Multipart message (may contain attachments)")
            elif 'text/html' in content_type.lower():
                analysis_parts.append(f"  🌐 HTML message")
            elif 'text/plain' in content_type.lower():
                analysis_parts.append(f"  📝 Plain text message")
            
            analysis_parts.append("")
        
        return "\n".join(analysis_parts)
    
    def _analyze_delivery_path(self, headers_text, options=None):
        """Analyze email delivery path"""
        if options is None:
            options = {
                'show_timestamps': True,
                'show_delays': True,
                'show_servers': True,
                'reverse_order': False
            }
        
        try:
            msg = message_from_string(headers_text)
            received_headers = msg.get_all('Received') or []
            
            path_parts = []
            stats_parts = []
            
            path_parts.append("🛤️ EMAIL DELIVERY PATH")
            path_parts.append("=" * 40)
            path_parts.append("")
            
            if not received_headers:
                path_parts.append("No Received headers found")
                return {'path': "\n".join(path_parts), 'stats': ''}
            
            timestamps = []
            servers = []
            total_delay = 0
            
            # Process headers in correct order
            headers_to_process = received_headers if options['reverse_order'] else list(reversed(received_headers))
            
            for i, received in enumerate(headers_to_process):
                hop_num = len(received_headers) - i if options['reverse_order'] else i + 1
                
                path_parts.append(f"📍 Hop {hop_num}:")
                
                # Extract server information
                if options['show_servers']:
                    server_match = re.search(r'from\s+([^\s]+)', received)
                    if server_match:
                        server = server_match.group(1)
                        servers.append(server)
                        path_parts.append(f"  🖥️  Server: {server}")
                    
                    # Extract IP addresses
                    ip_matches = re.findall(r'\[(\d+\.\d+\.\d+\.\d+)\]', received)
                    for ip in ip_matches:
                        path_parts.append(f"  🌐 IP: {ip}")
                
                # Extract and process timestamp
                if options['show_timestamps']:
                    timestamp_match = re.search(r';(.+)$', received.replace('\n', ' '))
                    if timestamp_match:
                        timestamp_str = timestamp_match.group(1).strip()
                        try:
                            timestamp = parsedate_to_datetime(timestamp_str)
                            timestamps.append(timestamp)
                            path_parts.append(f"  ⏰ Time: {timestamp.strftime('%Y-%m-%d %H:%M:%S %Z')}")
                            
                            # Calculate delays
                            if options['show_delays'] and len(timestamps) > 1:
                                delay = (timestamps[-1] - timestamps[-2]).total_seconds()
                                total_delay += abs(delay)
                                if delay > 0:
                                    path_parts.append(f"  ⏱️  Delay: {delay:.1f} seconds")
                                elif delay < 0:
                                    path_parts.append(f"  ⚠️  Time regression: {abs(delay):.1f} seconds")
                                    
                        except Exception as e:
                            path_parts.append(f"  ⏰ Time: {timestamp_str} (parse error)")
                
                path_parts.append("")
            
            # Generate statistics
            stats_parts.append(f"📊 DELIVERY STATISTICS:")
            stats_parts.append(f"Total hops: {len(received_headers)}")
            
            if timestamps:
                stats_parts.append(f"Total delivery time: {total_delay:.1f} seconds")
                
                if total_delay < 10:
                    stats_parts.append("⚡ Very fast delivery")
                elif total_delay < 60:
                    stats_parts.append("✅ Normal delivery speed")
                elif total_delay < 300:
                    stats_parts.append("⏳ Moderate delivery delay")
                else:
                    stats_parts.append("🐌 Slow delivery detected")
            
            if servers:
                unique_servers = list(set(servers))
                stats_parts.append(f"Unique servers: {len(unique_servers)}")
                
                # Check for loops
                if len(servers) != len(unique_servers):
                    stats_parts.append("⚠️ Possible mail loops detected")
            
            return {
                'path': "\n".join(path_parts),
                'stats': "\n".join(stats_parts)
            }
            
        except Exception as e:
            return {
                'path': f"Error analyzing delivery path: {str(e)}",
                'stats': ''
            }
    
    def check_spf(self, domain, sender_ip=""):
        """Check SPF records for domain"""
        def _check_spf():
            try:
                self.logger.debug(f"Checking SPF for domain: {domain}")
                self.result_ready.emit(f"Checking SPF records for {domain}...", "INFO")
                
                # Query TXT records for SPF
                import subprocess
                import platform
                
                if platform.system().lower() == "windows":
                    cmd = ["nslookup", "-type=TXT", domain]
                else:
                    cmd = ["dig", "TXT", domain, "+short"]
                
                process = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                results = []
                spf_found = False
                
                if process.returncode == 0 and process.stdout.strip():
                    lines = process.stdout.strip().split('\n')
                    
                    for line in lines:
                        if 'v=spf1' in line.lower():
                            spf_found = True
                            results.append(f"✅ SPF Record Found:")
                            results.append(f"  {line.strip()}")
                            
                            # Parse SPF record
                            spf_analysis = self._analyze_spf_record(line, sender_ip)
                            results.extend(spf_analysis)
                            break
                    
                    if not spf_found:
                        results.append(f"❌ No SPF record found for {domain}")
                        results.append(f"💡 SPF helps prevent email spoofing")
                else:
                    results.append(f"❌ Could not query SPF records for {domain}")
                    if process.stderr:
                        results.append(f"Error: {process.stderr}")
                
                auth_data = {'results': '\n'.join(results)}
                self.analysis_ready.emit(auth_data, "authentication")
                self.result_ready.emit("SPF check completed", "SUCCESS")
                
            except Exception as e:
                self.result_ready.emit(f"SPF check error: {str(e)}", "ERROR")
                
        thread = threading.Thread(target=_check_spf)
        thread.daemon = True
        thread.start()
    
    def _analyze_spf_record(self, spf_record, sender_ip=""):
        """Analyze SPF record content"""
        analysis = []
        
        # Extract SPF mechanisms
        mechanisms = []
        if 'include:' in spf_record:
            includes = re.findall(r'include:([^\s]+)', spf_record)
            for include in includes:
                mechanisms.append(f"Include: {include}")
        
        if 'a:' in spf_record or ' a ' in spf_record:
            mechanisms.append("A record check enabled")
        
        if 'mx:' in spf_record or ' mx ' in spf_record:
            mechanisms.append("MX record check enabled")
        
        if 'ip4:' in spf_record:
            ip4s = re.findall(r'ip4:([^\s]+)', spf_record)
            for ip4 in ip4s:
                mechanisms.append(f"IPv4: {ip4}")
        
        if 'ip6:' in spf_record:
            ip6s = re.findall(r'ip6:([^\s]+)', spf_record)
            for ip6 in ip6s:
                mechanisms.append(f"IPv6: {ip6}")
        
        # Check policy
        if '~all' in spf_record:
            policy = "SoftFail (~all) - suspicious but not rejected"
        elif '-all' in spf_record:
            policy = "Fail (-all) - reject unauthorized senders"
        elif '+all' in spf_record:
            policy = "Pass (+all) - allow all senders (not recommended)"
        elif '?all' in spf_record:
            policy = "Neutral (?all) - no policy"
        else:
            policy = "Unknown policy"
        
        analysis.append(f"")
        analysis.append(f"📋 SPF Analysis:")
        if mechanisms:
            analysis.append(f"  Authorized mechanisms:")
            for mechanism in mechanisms:
                analysis.append(f"    • {mechanism}")
        
        analysis.append(f"  Policy: {policy}")
        
        # Test sender IP if provided
        if sender_ip:
            analysis.append(f"")
            analysis.append(f"🔍 Sender IP Test ({sender_ip}):")
            
            # Simple IP matching
            ip_authorized = False
            
            # Check direct IP matches
            if f'ip4:{sender_ip}' in spf_record:
                ip_authorized = True
                analysis.append(f"  ✅ IP directly authorized")
            
            if not ip_authorized:
                analysis.append(f"  ⚠️ IP not explicitly authorized (may pass via include/mx/a)")
        
        return analysis
    
    def check_dkim(self, domain):
        """Check DKIM records for domain"""
        def _check_dkim():
            try:
                self.logger.debug(f"Checking DKIM for domain: {domain}")
                self.result_ready.emit(f"Checking DKIM records for {domain}...", "INFO")
                
                results = []
                selectors = ['default', 'google', 'k1', 'k2', 'mail', 'dkim', 'selector1', 'selector2']
                dkim_found = False
                
                for selector in selectors:
                    dkim_domain = f"{selector}._domainkey.{domain}"
                    
                    try:
                        import subprocess
                        import platform
                        
                        if platform.system().lower() == "windows":
                            cmd = ["nslookup", "-type=TXT", dkim_domain]
                        else:
                            cmd = ["dig", "TXT", dkim_domain, "+short"]
                        
                        process = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                        
                        if process.returncode == 0 and process.stdout.strip():
                            lines = process.stdout.strip().split('\n')
                            for line in lines:
                                if 'v=DKIM1' in line or 'k=' in line or 'p=' in line:
                                    dkim_found = True
                                    results.append(f"✅ DKIM Record Found:")
                                    results.append(f"  Selector: {selector}")
                                    results.append(f"  Record: {line.strip()}")
                                    
                                    # Analyze DKIM record
                                    dkim_analysis = self._analyze_dkim_record(line)
                                    results.extend(dkim_analysis)
                                    results.append("")
                                    break
                    except:
                        continue
                
                if not dkim_found:
                    results.append(f"❌ No DKIM records found for {domain}")
                    results.append(f"💡 Checked selectors: {', '.join(selectors)}")
                    results.append(f"💡 DKIM provides email integrity and authenticity")
                
                auth_data = {'results': '\n'.join(results)}
                self.analysis_ready.emit(auth_data, "authentication")
                self.result_ready.emit("DKIM check completed", "SUCCESS")
                
            except Exception as e:
                self.result_ready.emit(f"DKIM check error: {str(e)}", "ERROR")
                
        thread = threading.Thread(target=_check_dkim)
        thread.daemon = True
        thread.start()
    
    def _analyze_dkim_record(self, dkim_record):
        """Analyze DKIM record content"""
        analysis = []
        
        # Parse DKIM parameters
        dkim_params = {}
        for param in dkim_record.split(';'):
            param = param.strip().replace('"', '')
            if '=' in param:
                key, value = param.split('=', 1)
                dkim_params[key.strip()] = value.strip()
        
        analysis.append(f"📋 DKIM Analysis:")
        
        if 'v' in dkim_params:
            analysis.append(f"  Version: {dkim_params['v']}")
        
        if 'k' in dkim_params:
            key_type = dkim_params['k']
            if key_type == 'rsa':
                analysis.append(f"  Key Type: RSA (standard)")
            else:
                analysis.append(f"  Key Type: {key_type}")
        
        if 'p' in dkim_params:
            public_key = dkim_params['p']
            if public_key:
                key_length = len(public_key)
                analysis.append(f"  Public Key: Present ({key_length} chars)")
                if key_length > 400:
                    analysis.append(f"    🔒 Strong key length")
                else:
                    analysis.append(f"    ⚠️ Shorter key length")
            else:
                analysis.append(f"  Public Key: Revoked (empty p= tag)")
        
        if 't' in dkim_params:
            flags = dkim_params['t']
            if 'y' in flags:
                analysis.append(f"  🧪 Test mode enabled")
            if 's' in flags:
                analysis.append(f"  🔒 Strict subdomain policy")
        
        return analysis
    
    def check_dmarc(self, domain):
        """Check DMARC records for domain"""
        def _check_dmarc():
            try:
                self.logger.debug(f"Checking DMARC for domain: {domain}")
                self.result_ready.emit(f"Checking DMARC records for {domain}...", "INFO")
                
                dmarc_domain = f"_dmarc.{domain}"
                
                import subprocess
                import platform
                
                if platform.system().lower() == "windows":
                    cmd = ["nslookup", "-type=TXT", dmarc_domain]
                else:
                    cmd = ["dig", "TXT", dmarc_domain, "+short"]
                
                process = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                results = []
                dmarc_found = False
                
                if process.returncode == 0 and process.stdout.strip():
                    lines = process.stdout.strip().split('\n')
                    
                    for line in lines:
                        if 'v=DMARC1' in line:
                            dmarc_found = True
                            results.append(f"✅ DMARC Record Found:")
                            results.append(f"  {line.strip()}")
                            
                            # Analyze DMARC record
                            dmarc_analysis = self._analyze_dmarc_record(line)
                            results.extend(dmarc_analysis)
                            break
                
                if not dmarc_found:
                    results.append(f"❌ No DMARC record found for {domain}")
                    results.append(f"💡 DMARC provides policy for handling auth failures")
                    results.append(f"💡 Helps prevent domain spoofing and phishing")
                
                auth_data = {'results': '\n'.join(results)}
                self.analysis_ready.emit(auth_data, "authentication")
                self.result_ready.emit("DMARC check completed", "SUCCESS")
                
            except Exception as e:
                self.result_ready.emit(f"DMARC check error: {str(e)}", "ERROR")
                
        thread = threading.Thread(target=_check_dmarc)
        thread.daemon = True
        thread.start()
    
    def _analyze_dmarc_record(self, dmarc_record):
        """Analyze DMARC record content"""
        analysis = []
        
        # Parse DMARC parameters
        dmarc_params = {}
        for param in dmarc_record.split(';'):
            param = param.strip().replace('"', '')
            if '=' in param:
                key, value = param.split('=', 1)
                dmarc_params[key.strip()] = value.strip()
        
        analysis.append(f"")
        analysis.append(f"📋 DMARC Analysis:")
        
        # Policy analysis
        if 'p' in dmarc_params:
            policy = dmarc_params['p']
            if policy == 'none':
                analysis.append(f"  Policy: Monitor only (p=none)")
                analysis.append(f"    📊 No action taken, monitoring phase")
            elif policy == 'quarantine':
                analysis.append(f"  Policy: Quarantine (p=quarantine)")
                analysis.append(f"    📥 Failed emails may go to spam")
            elif policy == 'reject':
                analysis.append(f"  Policy: Reject (p=reject)")
                analysis.append(f"    🚫 Failed emails are rejected")
        
        # Subdomain policy
        if 'sp' in dmarc_params:
            sp_policy = dmarc_params['sp']
            analysis.append(f"  Subdomain Policy: {sp_policy}")
        
        # Percentage
        if 'pct' in dmarc_params:
            percentage = dmarc_params['pct']
            analysis.append(f"  Enforcement: {percentage}% of messages")
            if int(percentage) < 100:
                analysis.append(f"    ⚠️ Partial enforcement enabled")
        
        # Reporting
        if 'rua' in dmarc_params:
            rua = dmarc_params['rua']
            analysis.append(f"  Aggregate Reports: {rua}")
        
        if 'ruf' in dmarc_params:
            ruf = dmarc_params['ruf']
            analysis.append(f"  Forensic Reports: {ruf}")
        
        # Alignment
        if 'adkim' in dmarc_params:
            adkim = dmarc_params['adkim']
            if adkim == 's':
                analysis.append(f"  DKIM Alignment: Strict")
            else:
                analysis.append(f"  DKIM Alignment: Relaxed")
        
        if 'aspf' in dmarc_params:
            aspf = dmarc_params['aspf']
            if aspf == 's':
                analysis.append(f"  SPF Alignment: Strict")
            else:
                analysis.append(f"  SPF Alignment: Relaxed")
        
        return analysis
    
    def check_ip_reputation(self, ip_address):
        """Check IP reputation using multiple sources"""
        def _check_reputation():
            try:
                self.logger.debug(f"Checking reputation for IP: {ip_address}")
                self.result_ready.emit(f"Checking reputation for {ip_address}...", "INFO")
                
                results = []
                results.append(f"🔍 IP REPUTATION CHECK: {ip_address}")
                results.append("=" * 40)
                results.append("")
                
                # Basic IP validation
                try:
                    import ipaddress
                    ip_obj = ipaddress.ip_address(ip_address)
                    
                    if ip_obj.is_private:
                        results.append("📍 IP Type: Private/Internal")
                        results.append("⚠️ Private IPs are not in public blacklists")
                    elif ip_obj.is_loopback:
                        results.append("📍 IP Type: Loopback")
                    elif ip_obj.is_multicast:
                        results.append("📍 IP Type: Multicast")
                    else:
                        results.append("📍 IP Type: Public")
                        
                        # Check some basic reputation indicators
                        results.append("")
                        results.append("🛡️ Reputation Checks:")
                        
                        # Simple reverse DNS check
                        try:
                            import socket
                            hostname = socket.gethostbyaddr(ip_address)
                            results.append(f"  Reverse DNS: {hostname[0]}")
                            
                            # Check if hostname looks suspicious
                            suspicious_patterns = ['temp', 'dynamic', 'dhcp', 'pool', 'dial']
                            hostname_lower = hostname[0].lower()
                            
                            suspicious_found = any(pattern in hostname_lower for pattern in suspicious_patterns)
                            if suspicious_found:
                                results.append(f"  ⚠️ Hostname suggests dynamic/temporary IP")
                            else:
                                results.append(f"  ✅ Hostname appears stable")
                                
                        except socket.herror:
                            results.append(f"  Reverse DNS: Not found")
                            results.append(f"  ⚠️ No reverse DNS may indicate poor reputation")
                        
                        # Simple blacklist check simulation
                        results.append("")
                        results.append("🚫 Blacklist Status:")
                        results.append("  💡 For real blacklist checking, use services like:")
                        results.append("    • Spamhaus Block List (SBL)")
                        results.append("    • Composite Blocking List (CBL)")
                        results.append("    • Exploits Block List (XBL)")
                        results.append("    • Policy Block List (PBL)")
                        results.append("")
                        results.append("  🔗 Check manually at:")
                        results.append(f"    • https://www.spamhaus.org/lookup/")
                        results.append(f"    • https://mxtoolbox.com/blacklists.aspx")
                        results.append(f"    • https://multirbl.valli.org/lookup/")
                        
                except ValueError:
                    results.append("❌ Invalid IP address format")
                
                results.append("")
                results.append("📊 Reputation Summary:")
                results.append("  Manual verification recommended for production use")
                results.append("  Consider using dedicated reputation services for automation")
                
                spam_data = {'results': '\n'.join(results)}
                self.analysis_ready.emit(spam_data, "spam")
                self.result_ready.emit("IP reputation check completed", "SUCCESS")
                
            except Exception as e:
                self.result_ready.emit(f"IP reputation check error: {str(e)}", "ERROR")
                
        thread = threading.Thread(target=_check_reputation)
        thread.daemon = True
        thread.start()


class MailAnalyzerWindow(QMainWindow):
    """Main application window for the Mail Header Analyzer"""
    
    def __init__(self):
        super().__init__()
        self.logger = Logger()
        self.mail_tools = MailAnalysisTools(self.logger)
        self.init_ui()
        self.setup_connections()
    
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("Mail Header Analyzer v2.0")
        self.setGeometry(100, 100, 1400, 900)
        
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create horizontal splitter for tabs and output
        splitter = QSplitter(Qt.Horizontal)
        
        # Create main analysis tabs
        self.analysis_tabs = QTabWidget()
        
        # Header Analysis Tab
        self.header_tab = self.create_header_analysis_tab()
        self.analysis_tabs.addTab(self.header_tab, "📧 Header Analysis")
        
        # SPF/DKIM/DMARC Tab
        self.auth_tab = self.create_authentication_tab()
        self.analysis_tabs.addTab(self.auth_tab, "🔐 Email Authentication")
        
        # Delivery Path Tab
        self.delivery_tab = self.create_delivery_path_tab()
        self.analysis_tabs.addTab(self.delivery_tab, "🛤️ Delivery Path")
        
        # Spam Analysis Tab
        self.spam_tab = self.create_spam_analysis_tab()
        self.analysis_tabs.addTab(self.spam_tab, "🛡️ Spam Analysis")
        
        # Create output section
        output_widget = self.create_output_section()
        
        # Add to splitter
        splitter.addWidget(self.analysis_tabs)
        splitter.addWidget(output_widget)
        splitter.setSizes([900, 500])
        
        main_layout.addWidget(splitter)
        
        # Setup menu and status bar
        self.setup_menu()
        self.setup_status_bar()
        
        # Show welcome message
        QTimer.singleShot(500, self.show_welcome_message)
    
    def create_header_analysis_tab(self):
        """Create the main header analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Header Input Section
        input_group = QGroupBox("📧 Email Header Input")
        input_layout = QVBoxLayout(input_group)
        
        # Input method selection
        method_layout = QHBoxLayout()
        method_layout.addWidget(QLabel("Input Method:"))
        
        self.input_method_combo = QComboBox()
        self.input_method_combo.addItems([
            "Paste Headers Directly",
            "Upload .eml File",
            "Load Sample Headers"
        ])
        method_layout.addWidget(self.input_method_combo)
        
        # File upload button
        self.upload_file_btn = QPushButton("📁 Browse & Upload .eml File")
        self.upload_file_btn.setVisible(False)
        method_layout.addWidget(self.upload_file_btn)
        
        method_layout.addStretch()
        input_layout.addLayout(method_layout)
        
        # File info label
        self.file_info_label = QLabel()
        self.file_info_label.setVisible(False)
        self.file_info_label.setStyleSheet("""
            QLabel {
                background-color: #e8f4fd;
                border: 1px solid #0078d4;
                border-radius: 4px;
                padding: 8px;
                color: #0078d4;
                font-weight: bold;
            }
        """)
        input_layout.addWidget(self.file_info_label)
        
        # Header text input
        self.header_input = QTextEdit()
        self.header_input.setPlaceholderText(
            "Paste email headers here...\n\n"
            "Example headers to paste:\n"
            "Received: from mail.example.com...\n"
            "From: sender@example.com\n"
            "To: recipient@example.com\n"
            "Subject: Your Email Subject\n"
            "Date: Mon, 1 Jan 2024 12:00:00 +0000\n"
            "Message-ID: <123456@example.com>\n"
            "...\n\n"
            "Tip: Copy headers from 'View Source' or 'Show Original' in your email client"
        )
        self.header_input.setMinimumHeight(200)
        self.header_input.setFont(QFont("Consolas", 10))
        input_layout.addWidget(self.header_input)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        self.analyze_headers_btn = QPushButton("🔍 Analyze Headers")
        self.load_sample_btn = QPushButton("📋 Load Sample")
        self.clear_input_btn = QPushButton("🗑️ Clear Input")
        self.export_results_btn = QPushButton("💾 Export Results")
        
        button_layout.addWidget(self.analyze_headers_btn)
        button_layout.addWidget(self.load_sample_btn)
        button_layout.addWidget(self.clear_input_btn)
        button_layout.addWidget(self.export_results_btn)
        button_layout.addStretch()
        
        input_layout.addLayout(button_layout)
        layout.addWidget(input_group)
        
        # Analysis Results Section
        results_group = QGroupBox("📊 Header Analysis Results")
        results_layout = QVBoxLayout(results_group)
        
        # Create splitter for organized results display
        results_splitter = QSplitter(Qt.Horizontal)
        
        # Left side: Header tree view
        self.header_tree = QTreeWidget()
        self.header_tree.setHeaderLabels(["Header Field", "Value"])
        self.header_tree.setMinimumWidth(400)
        results_splitter.addWidget(self.header_tree)
        
        # Right side: Analysis details
        analysis_widget = QWidget()
        analysis_layout = QVBoxLayout(analysis_widget)
        
        # Quick summary
        self.summary_text = QTextEdit()
        self.summary_text.setMaximumHeight(150)
        self.summary_text.setReadOnly(True)
        self.summary_text.setStyleSheet("""
            QTextEdit {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 4px;
                padding: 8px;
            }
        """)
        analysis_layout.addWidget(QLabel("📊 Quick Summary:"))
        analysis_layout.addWidget(self.summary_text)
        
        # Detailed analysis
        self.analysis_text = QTextEdit()
        self.analysis_text.setReadOnly(True)
        self.analysis_text.setFont(QFont("Consolas", 9))
        analysis_layout.addWidget(QLabel("🔍 Detailed Analysis:"))
        analysis_layout.addWidget(self.analysis_text)
        
        results_splitter.addWidget(analysis_widget)
        results_splitter.setSizes([400, 600])
        
        results_layout.addWidget(results_splitter)
        layout.addWidget(results_group)
        
        # Style the header analysis buttons
        self.style_header_buttons()
        
        return widget
    
    def create_authentication_tab(self):
        """Create the email authentication analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Domain Input Section
        domain_group = QGroupBox("🔐 Email Authentication Analysis")
        domain_layout = QVBoxLayout(domain_group)
        
        # Input fields
        input_layout = QHBoxLayout()
        
        input_layout.addWidget(QLabel("Domain:"))
        self.auth_domain_edit = QLineEdit()
        self.auth_domain_edit.setPlaceholderText("example.com")
        input_layout.addWidget(self.auth_domain_edit)
        
        input_layout.addWidget(QLabel("Sender IP:"))
        self.sender_ip_edit = QLineEdit()
        self.sender_ip_edit.setPlaceholderText("192.168.1.100 (optional)")
        input_layout.addWidget(self.sender_ip_edit)
        
        domain_layout.addLayout(input_layout)
        
        # Authentication test buttons
        auth_button_layout = QHBoxLayout()
        
        self.spf_check_btn = QPushButton("🛡️ Check SPF")
        self.dkim_check_btn = QPushButton("🔑 Check DKIM")
        self.dmarc_check_btn = QPushButton("📋 Check DMARC")
        self.comprehensive_auth_btn = QPushButton("🔒 Full Auth Analysis")
        
        auth_button_layout.addWidget(self.spf_check_btn)
        auth_button_layout.addWidget(self.dkim_check_btn)
        auth_button_layout.addWidget(self.dmarc_check_btn)
        auth_button_layout.addWidget(self.comprehensive_auth_btn)
        
        domain_layout.addLayout(auth_button_layout)
        layout.addWidget(domain_group)
        
        # Style authentication buttons
        self.style_auth_buttons()
        
        # Authentication Results
        auth_results_group = QGroupBox("🔍 Authentication Analysis Results")
        auth_results_layout = QVBoxLayout(auth_results_group)
        
        self.auth_results_text = QTextEdit()
        self.auth_results_text.setReadOnly(True)
        self.auth_results_text.setFont(QFont("Consolas", 10))
        auth_results_layout.addWidget(self.auth_results_text)
        
        layout.addWidget(auth_results_group)
        
        # Authentication Guide
        guide_group = QGroupBox("💡 Email Authentication Guide")
        guide_layout = QVBoxLayout(guide_group)
        
        guide_text = QTextEdit()
        guide_text.setMaximumHeight(120)
        guide_text.setReadOnly(True)
        guide_text.setText(
            "Email Authentication Overview:\n"
            "• SPF (Sender Policy Framework): Validates sending IP against DNS records\n"
            "• DKIM (DomainKeys Identified Mail): Cryptographic signature validation\n"
            "• DMARC (Domain Message Authentication): Policy for handling auth failures\n"
            "• Use 'Full Auth Analysis' for complete domain security assessment\n"
            "• Results help diagnose email delivery issues and spam problems"
        )
        guide_layout.addWidget(guide_text)
        
        layout.addWidget(guide_group)
        layout.addStretch()
        
        return widget
    
    def create_delivery_path_tab(self):
        """Create the delivery path analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Delivery Path Analysis
        path_group = QGroupBox("🛤️ Email Delivery Path Analysis")
        path_layout = QVBoxLayout(path_group)
        
        # Options
        options_layout = QHBoxLayout()
        
        self.show_timestamps_cb = QCheckBox("Show Timestamps")
        self.show_timestamps_cb.setChecked(True)
        
        self.show_delays_cb = QCheckBox("Calculate Delays")
        self.show_delays_cb.setChecked(True)
        
        self.show_servers_cb = QCheckBox("Analyze Servers")
        self.show_servers_cb.setChecked(True)
        
        self.reverse_order_cb = QCheckBox("Reverse Order (Newest First)")
        self.reverse_order_cb.setChecked(False)
        
        options_layout.addWidget(self.show_timestamps_cb)
        options_layout.addWidget(self.show_delays_cb)
        options_layout.addWidget(self.show_servers_cb)
        options_layout.addWidget(self.reverse_order_cb)
        options_layout.addStretch()
        
        path_layout.addLayout(options_layout)
        
        # Delivery path visualization
        self.delivery_path_text = QTextEdit()
        self.delivery_path_text.setReadOnly(True)
        self.delivery_path_text.setFont(QFont("Consolas", 10))
        path_layout.addWidget(self.delivery_path_text)
        
        layout.addWidget(path_group)
        
        # Delivery Statistics
        stats_group = QGroupBox("📊 Delivery Statistics")
        stats_layout = QVBoxLayout(stats_group)
        
        self.delivery_stats_text = QTextEdit()
        self.delivery_stats_text.setMaximumHeight(100)
        self.delivery_stats_text.setReadOnly(True)
        stats_layout.addWidget(self.delivery_stats_text)
        
        layout.addWidget(stats_group)
        layout.addStretch()
        
        return widget
    
    def create_spam_analysis_tab(self):
        """Create the spam analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # IP Reputation Check
        reputation_group = QGroupBox("🔍 IP Reputation Check")
        reputation_layout = QVBoxLayout(reputation_group)
        
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("IP Address:"))
        self.reputation_ip_edit = QLineEdit()
        self.reputation_ip_edit.setPlaceholderText("Enter IP from headers")
        input_layout.addWidget(self.reputation_ip_edit)
        
        self.check_reputation_btn = QPushButton("🔍 Check Reputation")
        input_layout.addWidget(self.check_reputation_btn)
        
        reputation_layout.addLayout(input_layout)
        layout.addWidget(reputation_group)
        
        # Style reputation button
        self.style_reputation_button()
        
        # Spam analysis results
        spam_group = QGroupBox("🛡️ Spam Analysis Results")
        spam_layout = QVBoxLayout(spam_group)
        
        self.spam_results_text = QTextEdit()
        self.spam_results_text.setReadOnly(True)
        self.spam_results_text.setFont(QFont("Consolas", 10))
        spam_layout.addWidget(self.spam_results_text)
        
        layout.addWidget(spam_group)
        
        # Spam Analysis Guide
        guide_group = QGroupBox("💡 Spam Analysis Guide")
        guide_layout = QVBoxLayout(guide_group)
        
        guide_text = QTextEdit()
        guide_text.setMaximumHeight(120)
        guide_text.setReadOnly(True)
        guide_text.setText(
            "Spam Analysis Features:\n"
            "• IP reputation checking against known databases\n"
            "• Reverse DNS lookup for sender validation\n"
            "• Pattern analysis for suspicious content indicators\n"
            "• Blacklist verification recommendations\n"
            "• Security assessment for email filtering decisions"
        )
        guide_layout.addWidget(guide_text)
        
        layout.addWidget(guide_group)
        layout.addStretch()
        
        return widget
    
    def create_output_section(self):
        """Create the output/logging section"""
        output_widget = QWidget()
        output_layout = QVBoxLayout(output_widget)
        
        # Output header
        header_layout = QHBoxLayout()
        output_header = QLabel("📋 Analysis Output & Logs")
        output_header.setFont(QFont("Arial", 12, QFont.Bold))
        output_header.setStyleSheet("color: #0078d4; padding: 5px;")
        header_layout.addWidget(output_header)
        
        # Controls
        self.clear_output_btn = QPushButton("Clear")
        self.copy_output_btn = QPushButton("Copy")
        self.debug_btn = QPushButton("Debug")
        self.debug_btn.setCheckable(True)
        
        for btn in [self.clear_output_btn, self.copy_output_btn, self.debug_btn]:
            btn.setMaximumWidth(80)
        
        header_layout.addStretch()
        header_layout.addWidget(self.clear_output_btn)
        header_layout.addWidget(self.copy_output_btn)
        header_layout.addWidget(self.debug_btn)
        
        output_layout.addLayout(header_layout)
        
        # Output text area
        self.output_text = QTextEdit()
        self.output_text.setFont(QFont("Consolas", 10))
        self.output_text.setReadOnly(True)
        self.output_text.setMinimumWidth(400)
        self.output_text.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 2px solid #555;
                border-radius: 6px;
                padding: 8px;
                selection-background-color: #0078d4;
            }
        """)
        
        output_layout.addWidget(self.output_text)
        return output_widget
    
    def style_header_buttons(self):
        """Apply styling to header analysis buttons"""
        primary_style = """
            QPushButton {
                background-color: #0078d4;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
                min-height: 30px;
            }
            QPushButton:hover {
                background-color: #106ebe;
            }
            QPushButton:pressed {
                background-color: #005a9e;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """
        
        secondary_style = """
            QPushButton {
                background-color: #107c10;
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #0e6b0e;
            }
            QPushButton:pressed {
                background-color: #0c5a0c;
            }
        """
        
        # Apply styles to header analysis buttons
        self.analyze_headers_btn.setStyleSheet(primary_style)
        self.load_sample_btn.setStyleSheet(secondary_style)
        self.clear_input_btn.setStyleSheet(secondary_style)
        self.export_results_btn.setStyleSheet(secondary_style)
        self.upload_file_btn.setStyleSheet(secondary_style)
    
    def style_auth_buttons(self):
        """Apply styling to authentication buttons"""
        primary_style = """
            QPushButton {
                background-color: #0078d4;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
                min-height: 30px;
            }
            QPushButton:hover {
                background-color: #106ebe;
            }
            QPushButton:pressed {
                background-color: #005a9e;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """
        
        auth_style = """
            QPushButton {
                background-color: #d83b01;
                color: white;
                border: none;
                padding: 8px 12px;
                border-radius: 4px;
                font-weight: bold;
                min-height: 35px;
            }
            QPushButton:hover {
                background-color: #c23101;
            }
            QPushButton:pressed {
                background-color: #a62d01;
            }
        """
        
        # Apply styles to authentication buttons
        self.spf_check_btn.setStyleSheet(auth_style)
        self.dkim_check_btn.setStyleSheet(auth_style)
        self.dmarc_check_btn.setStyleSheet(auth_style)
        self.comprehensive_auth_btn.setStyleSheet(primary_style)
    
    def style_reputation_button(self):
        """Apply styling to reputation button"""
        auth_style = """
            QPushButton {
                background-color: #d83b01;
                color: white;
                border: none;
                padding: 8px 12px;
                border-radius: 4px;
                font-weight: bold;
                min-height: 35px;
            }
            QPushButton:hover {
                background-color: #c23101;
            }
            QPushButton:pressed {
                background-color: #a62d01;
            }
        """
        
        # Apply style to reputation button
        self.check_reputation_btn.setStyleSheet(auth_style)
    
    def style_buttons(self):
        """Apply consistent styling to buttons (legacy method - kept for compatibility)"""
        # This method is kept for compatibility but styling is now done
        # in individual style_*_buttons() methods called from each tab creation
        pass
    
    def setup_connections(self):
        """Setup signal connections"""
        # Header analysis connections
        self.analyze_headers_btn.clicked.connect(self.analyze_email_headers)
        self.load_sample_btn.clicked.connect(self.load_sample_headers)
        self.clear_input_btn.clicked.connect(self.clear_input)
        self.export_results_btn.clicked.connect(self.export_results)
        self.upload_file_btn.clicked.connect(self.upload_eml_file)
        
        # Input method change
        self.input_method_combo.currentTextChanged.connect(self.on_input_method_changed)
        
        # Authentication connections
        self.spf_check_btn.clicked.connect(self.check_spf)
        self.dkim_check_btn.clicked.connect(self.check_dkim)
        self.dmarc_check_btn.clicked.connect(self.check_dmarc)
        self.comprehensive_auth_btn.clicked.connect(self.comprehensive_auth_check)
        self.check_reputation_btn.clicked.connect(self.check_ip_reputation)
        
        # Output connections
        self.clear_output_btn.clicked.connect(self.clear_output)
        self.copy_output_btn.clicked.connect(self.copy_output)
        self.debug_btn.toggled.connect(self.toggle_debug)
        
        # Mail tools connections
        self.mail_tools.result_ready.connect(self.handle_result)
        self.mail_tools.analysis_ready.connect(self.handle_analysis)
        
        # Logger connection
        self.logger.message_logged.connect(self.append_output)
        
        # Auto-extract domain from headers
        self.header_input.textChanged.connect(self.auto_extract_domain)
        
        # Delivery path options
        self.show_timestamps_cb.toggled.connect(self.update_delivery_path)
        self.show_delays_cb.toggled.connect(self.update_delivery_path)
        self.show_servers_cb.toggled.connect(self.update_delivery_path)
        self.reverse_order_cb.toggled.connect(self.update_delivery_path)
    
    def setup_menu(self):
        """Setup application menu"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('File')
        
        # New analysis
        new_action = QAction('New Analysis', self)
        new_action.setShortcut('Ctrl+N')
        new_action.triggered.connect(self.clear_input)
        file_menu.addAction(new_action)
        
        # Open .eml file
        open_action = QAction('Open .eml File...', self)
        open_action.setShortcut('Ctrl+O')
        open_action.triggered.connect(self.upload_eml_file)
        file_menu.addAction(open_action)
        
        file_menu.addSeparator()
        
        # Export results
        export_action = QAction('Export Results...', self)
        export_action.setShortcut('Ctrl+E')
        export_action.triggered.connect(self.export_results)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        # Exit
        exit_action = QAction('Exit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools menu
        tools_menu = menubar.addMenu('Tools')
        
        # Load sample
        sample_action = QAction('Load Sample Headers', self)
        sample_action.triggered.connect(self.load_sample_headers)
        tools_menu.addAction(sample_action)
        
        tools_menu.addSeparator()
        
        # Quick authentication checks
        spf_action = QAction('Quick SPF Check', self)
        spf_action.triggered.connect(self.check_spf)
        tools_menu.addAction(spf_action)
        
        dkim_action = QAction('Quick DKIM Check', self)
        dkim_action.triggered.connect(self.check_dkim)
        tools_menu.addAction(dkim_action)
        
        dmarc_action = QAction('Quick DMARC Check', self)
        dmarc_action.triggered.connect(self.check_dmarc)
        tools_menu.addAction(dmarc_action)
        
        # Help menu
        help_menu = menubar.addMenu('Help')
        
        about_action = QAction('About', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
        help_action = QAction('User Guide', self)
        help_action.triggered.connect(self.show_help)
        help_menu.addAction(help_action)
    
    def setup_status_bar(self):
        """Setup status bar"""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready - Load email headers to begin analysis")
    
    def show_welcome_message(self):
        """Show welcome message"""
        self.logger.info("🎉 Welcome to Mail Header Analyzer v2.0!")
        self.logger.info("📧 Comprehensive email header analysis and security checking")
        self.logger.info("🔐 SPF, DKIM, DMARC validation and delivery path analysis")
        self.logger.info("🛡️ Spam detection and IP reputation checking")
        self.logger.info("💡 Ready to analyze - paste headers or upload .eml files!")
    
    # Event handlers and analysis methods
    def on_input_method_changed(self, method):
        """Handle input method selection change"""
        if method == "Upload .eml File":
            self.upload_file_btn.setVisible(True)
            self.header_input.setPlaceholderText(
                "Click 'Browse & Upload .eml File' button above to load email from file...\n\n"
                "Supported formats:\n"
                "• .eml files (standard email format)\n"
                "• .msg files (Outlook format - experimental)\n"
                "• .txt files containing email headers\n\n"
                "Or manually paste headers below if you prefer."
            )
        elif method == "Load Sample Headers":
            self.upload_file_btn.setVisible(False)
            self.file_info_label.setVisible(False)
            self.load_sample_headers()
        else:
            self.upload_file_btn.setVisible(False)
            self.file_info_label.setVisible(False)
            self.header_input.setPlaceholderText(
                "Paste email headers here...\n\n"
                "Example headers to paste:\n"
                "Received: from mail.example.com...\n"
                "From: sender@example.com\n"
                "To: recipient@example.com\n"
                "Subject: Your Email Subject\n"
                "Date: Mon, 1 Jan 2024 12:00:00 +0000\n"
                "Message-ID: <123456@example.com>\n"
                "...\n\n"
                "Tip: Copy headers from 'View Source' or 'Show Original' in your email client"
            )
    
    def upload_eml_file(self):
        """Handle .eml file upload"""
        try:
            file_path, _ = QFileDialog.getOpenFileName(
                self,
                "Select Email File",
                "",
                "Email Files (*.eml *.msg *.txt);;All Files (*)"
            )
            
            if file_path:
                self.logger.info(f"Loading email file: {file_path}")
                
                # Read the file
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        file_content = f.read()
                except UnicodeDecodeError:
                    # Try with different encoding
                    try:
                        with open(file_path, 'r', encoding='latin-1') as f:
                            file_content = f.read()
                    except Exception as e:
                        self.logger.error(f"Could not read file with any encoding: {str(e)}")
                        return
                
                # Check if it's a valid email format
                if not self.validate_email_content(file_content):
                    reply = QMessageBox.question(
                        self, 
                        "Invalid Email Format", 
                        "The selected file doesn't appear to contain valid email headers.\n\n"
                        "Do you want to load it anyway?",
                        QMessageBox.Yes | QMessageBox.No,
                        QMessageBox.No
                    )
                    if reply == QMessageBox.No:
                        return
                
                # Load content into text area
                self.header_input.setPlainText(file_content)
                
                # Show file info
                import os
                file_name = os.path.basename(file_path)
                file_size = os.path.getsize(file_path)
                self.file_info_label.setText(
                    f"📁 Loaded: {file_name} ({file_size:,} bytes)"
                )
                self.file_info_label.setVisible(True)
                
                self.logger.success(f"Successfully loaded email file: {file_name}")
                self.status_bar.showMessage(f"Loaded: {file_name}")
                
                # Auto-extract domain information
                self.auto_extract_domain()
                
        except Exception as e:
            self.logger.error(f"Failed to upload file: {str(e)}")
    
    def validate_email_content(self, content):
        """Validate if content contains email headers"""
        # Check for common email headers
        email_headers = [
            'from:', 'to:', 'subject:', 'date:', 'message-id:', 
            'received:', 'return-path:', 'mime-version:'
        ]
        
        content_lower = content.lower()
        found_headers = sum(1 for header in email_headers if header in content_lower)
        
        # Consider valid if at least 3 common headers are found
        return found_headers >= 3
    
    def analyze_email_headers(self):
        """Analyze email headers"""
        headers_text = self.header_input.toPlainText().strip()
        if not headers_text:
            self.logger.error("Please paste email headers to analyze or upload an .eml file")
            QMessageBox.warning(self, "No Headers", "Please paste email headers or upload a file.")
            return
        
        self.analyze_headers_btn.setEnabled(False)
        self.analyze_headers_btn.setText("⏳ Analyzing...")
        self.status_bar.showMessage("Analyzing email headers...")
        
        # Clear previous results
        self.header_tree.clear()
        self.summary_text.clear()
        self.analysis_text.clear()
        
        self.logger.info("🔍 Starting comprehensive header analysis...")
        self.mail_tools.analyze_headers(headers_text)
        
        # Re-enable button after delay
        QTimer.singleShot(3000, self.restore_analyze_button)
    
    def restore_analyze_button(self):
        """Restore analyze button state"""
        self.analyze_headers_btn.setEnabled(True)
        self.analyze_headers_btn.setText("🔍 Analyze Headers")
    
    def load_sample_headers(self):
        """Load sample email headers for testing"""
        sample_headers = """Delivered-To: user@example.com
Received: by 2002:a17:90b:1234:b0:1a2:3b4c:5d6e with SMTP id abc123-v1.1.1.1
        for <user@example.com>; Mon, 27 May 2024 10:30:15 -0700 (PDT)
Received: from mail.sender.com (mail.sender.com. [203.0.113.10])
        by mx.google.com with ESMTPS id xyz789-v6.0.1.1
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 27 May 2024 10:30:14 -0700 (PDT)
Received: from internal.sender.com (internal.sender.com [192.168.1.50])
        by mail.sender.com with ESMTP id qwerty123;
        Mon, 27 May 2024 17:30:13 +0000
Message-ID: <20240527173013.ABC123@sender.com>
Date: Mon, 27 May 2024 17:30:13 +0000
From: "John Doe" <john.doe@sender.com>
To: user@example.com
Subject: Test Email for Header Analysis
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of john.doe@sender.com designates 203.0.113.10 as permitted sender) smtp.mailfrom=john.doe@sender.com;
       dkim=pass (test mode) header.i=@sender.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=sender.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=sender.com; s=default;
        h=from:to:subject:date:message-id; bh=abc123def456==; b=xyz789abc123==
SPF: PASS
Return-Path: <john.doe@sender.com>

This is a sample email for testing header analysis functionality."""

        self.header_input.setPlainText(sample_headers)
        self.file_info_label.setVisible(False)  # Hide file info when loading sample
        self.logger.info("📋 Sample email headers loaded")
        self.status_bar.showMessage("Sample headers loaded")
        
        # Auto-extract domain info
        self.auto_extract_domain()
    
    def clear_input(self):
        """Clear all input fields"""
        self.header_input.clear()
        self.header_tree.clear()
        self.summary_text.clear()
        self.analysis_text.clear()
        self.auth_results_text.clear()
        self.delivery_path_text.clear()
        self.delivery_stats_text.clear()
        self.spam_results_text.clear()
        self.file_info_label.setVisible(False)
        self.auth_domain_edit.clear()
        self.sender_ip_edit.clear()
        self.reputation_ip_edit.clear()
        self.logger.info("🗑️ Input and results cleared")
        self.status_bar.showMessage("Ready - Load email headers to begin analysis")
    
    def auto_extract_domain(self):
        """Auto-extract domain from headers for authentication checks"""
        headers_text = self.header_input.toPlainText()
        
        # Try to extract domain from From field
        import re
        from_match = re.search(r'From:.*?@([a-zA-Z0-9.-]+)', headers_text, re.IGNORECASE)
        if from_match and not self.auth_domain_edit.text():
            domain = from_match.group(1)
            self.auth_domain_edit.setText(domain)
        
        # Try to extract sender IP from Received headers
        ip_match = re.search(r'Received:.*?\[(\d+\.\d+\.\d+\.\d+)\]', headers_text)
        if ip_match and not self.sender_ip_edit.text():
            ip = ip_match.group(1)
            self.sender_ip_edit.setText(ip)
            self.reputation_ip_edit.setText(ip)
    
    def check_spf(self):
        """Check SPF records for domain"""
        domain = self.auth_domain_edit.text().strip()
        sender_ip = self.sender_ip_edit.text().strip()
        
        if not domain:
            self.logger.error("Please enter a domain to check SPF")
            QMessageBox.warning(self, "Missing Domain", "Please enter a domain to check SPF records.")
            return
        
        self.spf_check_btn.setEnabled(False)
        self.spf_check_btn.setText("⏳ Checking...")
        self.status_bar.showMessage(f"Checking SPF records for {domain}...")
        
        self.logger.info(f"🛡️ Checking SPF records for {domain}...")
        self.mail_tools.check_spf(domain, sender_ip)
        
        QTimer.singleShot(5000, lambda: self.restore_button(self.spf_check_btn, "🛡️ Check SPF"))
    
    def check_dkim(self):
        """Check DKIM records for domain"""
        domain = self.auth_domain_edit.text().strip()
        
        if not domain:
            self.logger.error("Please enter a domain to check DKIM")
            QMessageBox.warning(self, "Missing Domain", "Please enter a domain to check DKIM records.")
            return
        
        self.dkim_check_btn.setEnabled(False)
        self.dkim_check_btn.setText("⏳ Checking...")
        self.status_bar.showMessage(f"Checking DKIM records for {domain}...")
        
        self.logger.info(f"🔑 Checking DKIM records for {domain}...")
        self.mail_tools.check_dkim(domain)
        
        QTimer.singleShot(5000, lambda: self.restore_button(self.dkim_check_btn, "🔑 Check DKIM"))
    
    def check_dmarc(self):
        """Check DMARC records for domain"""
        domain = self.auth_domain_edit.text().strip()
        
        if not domain:
            self.logger.error("Please enter a domain to check DMARC")
            QMessageBox.warning(self, "Missing Domain", "Please enter a domain to check DMARC records.")
            return
        
        self.dmarc_check_btn.setEnabled(False)
        self.dmarc_check_btn.setText("⏳ Checking...")
        self.status_bar.showMessage(f"Checking DMARC records for {domain}...")
        
        self.logger.info(f"📋 Checking DMARC records for {domain}...")
        self.mail_tools.check_dmarc(domain)
        
        QTimer.singleShot(5000, lambda: self.restore_button(self.dmarc_check_btn, "📋 Check DMARC"))
    
    def comprehensive_auth_check(self):
        """Run comprehensive authentication check"""
        domain = self.auth_domain_edit.text().strip()
        sender_ip = self.sender_ip_edit.text().strip()
        
        if not domain:
            self.logger.error("Please enter a domain for comprehensive check")
            QMessageBox.warning(self, "Missing Domain", "Please enter a domain for comprehensive authentication check.")
            return
        
        self.comprehensive_auth_btn.setEnabled(False)
        self.comprehensive_auth_btn.setText("⏳ Analyzing...")
        self.status_bar.showMessage(f"Running comprehensive authentication analysis for {domain}...")
        
        self.logger.info(f"🔒 Running comprehensive authentication analysis for {domain}...")
        
        # Clear previous results
        self.auth_results_text.clear()
        
        # Run all checks in sequence
        def run_comprehensive():
            self.mail_tools.check_spf(domain, sender_ip)
            time.sleep(2)
            self.mail_tools.check_dkim(domain)
            time.sleep(2)
            self.mail_tools.check_dmarc(domain)
        
        thread = threading.Thread(target=run_comprehensive)
        thread.daemon = True
        thread.start()
        
        QTimer.singleShot(15000, lambda: self.restore_button(self.comprehensive_auth_btn, "🔒 Full Auth Analysis"))
    
    def check_ip_reputation(self):
        """Check IP reputation"""
        ip = self.reputation_ip_edit.text().strip()
        
        if not ip:
            self.logger.error("Please enter an IP address to check")
            QMessageBox.warning(self, "Missing IP", "Please enter an IP address to check reputation.")
            return
        
        self.check_reputation_btn.setEnabled(False)
        self.check_reputation_btn.setText("⏳ Checking...")
        self.status_bar.showMessage(f"Checking reputation for IP {ip}...")
        
        self.logger.info(f"🔍 Checking reputation for IP {ip}...")
        self.mail_tools.check_ip_reputation(ip)
        
        QTimer.singleShot(10000, lambda: self.restore_button(self.check_reputation_btn, "🔍 Check Reputation"))
    
    def restore_button(self, button, original_text):
        """Restore button to original state"""
        button.setEnabled(True)
        button.setText(original_text)
    
    def update_delivery_path(self):
        """Update delivery path display based on options"""
        headers_text = self.header_input.toPlainText()
        if headers_text:
            options = {
                'show_timestamps': self.show_timestamps_cb.isChecked(),
                'show_delays': self.show_delays_cb.isChecked(),
                'show_servers': self.show_servers_cb.isChecked(),
                'reverse_order': self.reverse_order_cb.isChecked()
            }
            
            # Re-analyze delivery path with new options
            delivery_data = self.mail_tools._analyze_delivery_path(headers_text, options)
            self.delivery_path_text.setPlainText(delivery_data['path'])
            self.delivery_stats_text.setPlainText(delivery_data['stats'])
    
    def export_results(self):
        """Export analysis results"""
        try:
            # Get all results
            headers = self.header_input.toPlainText()
            summary = self.summary_text.toPlainText()
            analysis = self.analysis_text.toPlainText()
            auth_results = self.auth_results_text.toPlainText()
            delivery_path = self.delivery_path_text.toPlainText()
            spam_results = self.spam_results_text.toPlainText()
            
            if not any([headers, summary, analysis, auth_results, delivery_path, spam_results]):
                self.logger.warning("No analysis results to export")
                QMessageBox.information(self, "No Results", "No analysis results to export. Please run some analysis first.")
                return
            
            # Choose file location
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Export Analysis Results", 
                f"mail_analysis_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt", 
                "Text Files (*.txt);;All Files (*)"
            )
            
            if file_path:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("Mail Header Analyzer v2.0 - Analysis Results\n")
                    f.write("=" * 60 + "\n")
                    f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    
                    if headers:
                        f.write("ORIGINAL HEADERS:\n")
                        f.write("-" * 20 + "\n")
                        f.write(headers + "\n\n")
                    
                    if summary:
                        f.write("SUMMARY:\n")
                        f.write("-" * 20 + "\n")
                        f.write(summary + "\n\n")
                    
                    if analysis:
                        f.write("DETAILED ANALYSIS:\n")
                        f.write("-" * 20 + "\n")
                        f.write(analysis + "\n\n")
                    
                    if auth_results:
                        f.write("AUTHENTICATION RESULTS:\n")
                        f.write("-" * 20 + "\n")
                        f.write(auth_results + "\n\n")
                    
                    if delivery_path:
                        f.write("DELIVERY PATH:\n")
                        f.write("-" * 20 + "\n")
                        f.write(delivery_path + "\n\n")
                    
                    if spam_results:
                        f.write("SPAM ANALYSIS:\n")
                        f.write("-" * 20 + "\n")
                        f.write(spam_results + "\n\n")
                
                self.logger.success(f"✅ Results exported to: {file_path}")
                self.status_bar.showMessage(f"Results exported to: {os.path.basename(file_path)}")
                
        except Exception as e:
            self.logger.error(f"Export failed: {str(e)}")
    
    def handle_result(self, message, level):
        """Handle results from mail tools"""
        if level == "SUCCESS":
            self.logger.success(message)
        elif level == "ERROR":
            self.logger.error(message)
        elif level == "WARNING":
            self.logger.warning(message)
        else:
            self.logger.info(message)
    
    def handle_analysis(self, analysis_data, analysis_type):
        """Handle analysis results from mail tools"""
        if analysis_type == "headers":
            self.display_header_analysis(analysis_data)
        elif analysis_type == "authentication":
            self.display_auth_analysis(analysis_data)
        elif analysis_type == "spam":
            self.display_spam_analysis(analysis_data)
    
    def display_header_analysis(self, analysis_data):
        """Display header analysis results"""
        # Populate header tree
        self.header_tree.clear()
        if 'headers' in analysis_data:
            for header, value in analysis_data['headers'].items():
                item = QTreeWidgetItem([header, value])
                self.header_tree.addTopLevelItem(item)
        
        # Update summary
        if 'summary' in analysis_data:
            self.summary_text.setPlainText(analysis_data['summary'])
        
        # Update detailed analysis
        if 'analysis' in analysis_data:
            self.analysis_text.setPlainText(analysis_data['analysis'])
        
        # Update delivery path if available
        if 'delivery_path' in analysis_data:
            delivery_data = analysis_data['delivery_path']
            if isinstance(delivery_data, dict):
                self.delivery_path_text.setPlainText(delivery_data.get('path', ''))
                self.delivery_stats_text.setPlainText(delivery_data.get('stats', ''))
        
        self.status_bar.showMessage("Header analysis completed")
    
    def display_auth_analysis(self, analysis_data):
        """Display authentication analysis results"""
        current_text = self.auth_results_text.toPlainText()
        new_text = analysis_data.get('results', '')
        
        if current_text:
            self.auth_results_text.setPlainText(current_text + "\n\n" + new_text)
        else:
            self.auth_results_text.setPlainText(new_text)
    
    def display_spam_analysis(self, spam_data):
        """Display spam analysis results"""
        self.spam_results_text.setPlainText(spam_data.get('results', ''))
    
    def append_output(self, message):
        """Append message to output log"""
        self.output_text.append(message)
        # Auto-scroll to bottom
        cursor = self.output_text.textCursor()
        cursor.movePosition(cursor.End)
        self.output_text.setTextCursor(cursor)
    
    def clear_output(self):
        """Clear output log"""
        self.output_text.clear()
        self.logger.info("Output log cleared")
    
    def copy_output(self):
        """Copy output to clipboard"""
        clipboard = QApplication.clipboard()
        clipboard.setText(self.output_text.toPlainText())
        self.logger.info("Output copied to clipboard")
    
    def toggle_debug(self, enabled):
        """Toggle debug mode"""
        self.logger.set_debug_mode(enabled)
        status = "enabled" if enabled else "disabled"
        self.logger.info(f"Debug mode {status}")
    
    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(self, "About Mail Header Analyzer", 
                         "Mail Header Analyzer v2.0\n\n"
                         "A comprehensive standalone application for analyzing email headers, "
                         "authentication records, and spam detection.\n\n"
                         "Features:\n"
                         "• Complete email header analysis\n"
                         "• SPF, DKIM, DMARC authentication checking\n"
                         "• Delivery path visualization\n"
                         "• IP reputation and spam analysis\n"
                         "• .eml file support\n"
                         "• Export capabilities\n\n"
                         "Perfect for email administrators, security analysts, "
                         "and IT professionals diagnosing email delivery issues.")
    
    def show_help(self):
        """Show help dialog"""
        help_text = """📧 MAIL HEADER ANALYZER HELP

GETTING STARTED:
1. Paste email headers into the text area or upload an .eml file
2. Click "Analyze Headers" for comprehensive analysis
3. Use other tabs for specific authentication and spam checks

📧 HEADER ANALYSIS:
• Paste headers from 'View Source' or 'Show Original' in your email client
• Upload .eml files directly from saved emails
• Analyzes delivery path, authentication, and security indicators
• Identifies potential issues and suspicious patterns

🔐 EMAIL AUTHENTICATION:
• SPF: Validates sending IP against DNS records
• DKIM: Checks cryptographic signatures for integrity
• DMARC: Analyzes domain policies for handling failures
• Domain information is auto-extracted from headers

🛤️ DELIVERY PATH:
• Traces email route through mail servers
• Calculates delivery delays and identifies bottlenecks
• Detects potential mail loops or routing issues
• Customizable display options

🛡️ SPAM ANALYSIS:
• IP reputation checking and reverse DNS lookup
• Blacklist verification recommendations
• Security assessment for filtering decisions

💾 EXPORT & SAVE:
• Export complete analysis results to text files
• Save results for documentation and reports
• Copy individual sections or full output

💡 TIPS:
• Use 'Load Sample' to test with example headers
• Enable debug mode for detailed logging
• Domain and IP fields auto-populate from headers
• Results are color-coded for easy interpretation"""
        
        msg = QMessageBox()
        msg.setWindowTitle("Mail Header Analyzer Help")
        msg.setText("Mail Header Analyzer User Guide")
        msg.setDetailedText(help_text)
        msg.setIcon(QMessageBox.Information)
        msg.exec_()


def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    app.setApplicationName("Mail Header Analyzer")
    app.setApplicationVersion("2.0")
    app.setOrganizationName("Mail Analysis Tools")
    
    # Set application icon if available
    try:
        app.setWindowIcon(QIcon("mail_icon.png"))
    except:
        pass
    
    # Create and show main window
    window = MailAnalyzerWindow()
    window.show()
    
    # Run application
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()