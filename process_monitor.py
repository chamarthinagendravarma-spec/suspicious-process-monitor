 #!/usr/bin/env python3
"""
 Suspicious Process Detection System
 ====================================
 Monitors running processes and detects suspicious activity.
 """
import psutil
import json
import logging
import smtplib
import hashlib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from pathlib import Path
import time
import os
CONFIG_FILE = "config.json"
LOG_FILE = "suspicious_processes.log"
# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
 )
logger = logging.getLogger(__name__)
class ProcessMonitor:
    """Main class for monitoring processes"""
    
    def __init__(self, config_file=CONFIG_FILE):
        self.config = self.load_config(config_file)
        self.whitelist = set(self.config.get('whitelist', []))
        self.blacklist = set(self.config.get('blacklist', []))
        self.suspicious_count = 0
        
    def load_config(self, config_file):
        """Load configuration from JSON file"""
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                logger.info(f"Configuration loaded from {config_file}")
                return config
        except FileNotFoundError:
            logger.error(f"Config file {config_file} not found!")
            return {}
        except json.JSONDecodeError:
            logger.error(f"Error parsing {config_file}")
            return {}
    
    def calculate_process_hash(self, process_path):
        """Calculate SHA256 hash of executable"""
        try:
            if os.path.exists(process_path):
                with open(process_path, 'rb') as f:
                    file_hash = hashlib.sha256()
                    while chunk := f.read(8192):
                        file_hash.update(chunk)
                    return file_hash.hexdigest()
        except (PermissionError, OSError) as e:
            logger.debug(f"Cannot hash {process_path}: {e}")
        return None
    
    def is_suspicious(self, process):
        """Check if a process is suspicious"""
        try:
            proc_name = process.name().lower()
            
            # Check blacklist
            if proc_name in self.blacklist:
                return True, f"In blacklist"
            
            # Check whitelist
            if self.config.get('use_whitelist', False):
                if proc_name not in self.whitelist:
                    return True, f"Not in whitelist"
            
            # Check CPU usage
            cpu_percent = process.cpu_percent(interval=0.1)
            cpu_threshold = self.config.get('cpu_threshold', 90)
            if cpu_percent > cpu_threshold:
                return True, f"High CPU: {cpu_percent}%"
            
            # Check memory usage
            memory_info = process.memory_info()
            memory_mb = memory_info.rss / (1024 * 1024)
            memory_threshold = self.config.get('memory_threshold_mb', 1000)
            if memory_mb > memory_threshold:
                return True, f"High memory: {memory_mb:.2f} MB"
            
            return False, None
            
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False, None
    
    def get_process_info(self, process):
        """Extract detailed process information"""
        try:
            with process.oneshot():
                info = {
                    'pid': process.pid,
                    'name': process.name(),
                    'exe': process.exe() if hasattr(process, 'exe') else 'N/A',
                    'status': process.status(),
                    'username': process.username(),
                    'cpu_percent': process.cpu_percent(interval=0.1),
                    'memory_mb': process.memory_info().rss / (1024 * 1024),
                    'num_threads': process.num_threads(),
                    'create_time': datetime.fromtimestamp(
                        process.create_time()
                    ).strftime('%Y-%m-%d %H:%M:%S')
                }
                
                if info['exe'] != 'N/A':
                    info['file_hash'] = self.calculate_process_hash(info['exe'])
                
                return info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
    
    def send_email_alert(self, suspicious_processes):
        """Send email alert"""
        if not self.config.get('email_alerts_enabled', False):
            return
        
        try:
            smtp_config = self.config.get('smtp', {})
            sender_email = smtp_config.get('sender_email')
            sender_password = smtp_config.get('sender_password')
            receiver_email = smtp_config.get('receiver_email')
            smtp_server = smtp_config.get('smtp_server', 'smtp.gmail.com')
            smtp_port = smtp_config.get('smtp_port', 587)
            
            if not all([sender_email, sender_password, receiver_email]):
                logger.warning("Email config incomplete")
                return
            
            message = MIMEMultipart()
            message['From'] = sender_email
            message['To'] = receiver_email
            message['Subject'] = f"ALERT: {len(suspicious_processes)} Suspicious Process(es)"

            body = "Suspicious processes detected:\n\n"
            for proc_info, reason in suspicious_processes:
                body += f"Process: {proc_info['name']} (PID: {proc_info['pid']})\n"
                body += f"Reason: {reason}\n"
                body += f"Executable: {proc_info['exe']}\n"
                body += f"User: {proc_info['username']}\n"
                body += f"CPU: {proc_info['cpu_percent']:.2f}%\n"
                body += f"Memory: {proc_info['memory_mb']:.2f} MB\n"
                if proc_info.get('file_hash'):
                    body += f"Hash: {proc_info['file_hash']}\n"
                body += "-" * 50 + "\n\n"
            
            message.attach(MIMEText(body, 'plain'))
            
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(sender_email, sender_password)
                server.send_message(message)
                
            logger.info(f"Email alert sent to {receiver_email}")
            
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
    
    def scan_processes(self):
        """Scan all running processes"""
        suspicious_processes = []
        total_processes = 0
        
        logger.info("Starting process scan...")
        
        for process in psutil.process_iter():
            try:
                total_processes += 1
                is_susp, reason = self.is_suspicious(process)
                
                if is_susp:
                    proc_info = self.get_process_info(process)
                    if proc_info:
                        suspicious_processes.append((proc_info, reason))
                        self.suspicious_count += 1
                        logger.warning(
                            f"SUSPICIOUS: {proc_info['name']} "
                            f"(PID: {proc_info['pid']}) - {reason}"
                        )
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        logger.info(
            f"Scan complete. Checked {total_processes} processes, "
            f"found {len(suspicious_processes)} suspicious."
        )
        
        if suspicious_processes:
            self.send_email_alert(suspicious_processes)
        
        return suspicious_processes
    
    def run_continuous_monitoring(self, interval=60):
        """Run continuous monitoring"""
        logger.info(f"Starting continuous monitoring (interval: {interval}s)")
        
        try:
            while True:
                self.scan_processes()
                logger.info(f"Next scan in {interval} seconds...")
                time.sleep(interval)
        except KeyboardInterrupt:
            logger.info("\nMonitoring stopped by user")
            logger.info(f"Total suspicious: {self.suspicious_count}")
def main():
    """Main function"""
    print("=" * 60)
    print("Suspicious Process Detection System")
    print("=" * 60)
    
    if not Path(CONFIG_FILE).exists():
        logger.error(f"Configuration file '{CONFIG_FILE}' not found!")
        return
    
    monitor = ProcessMonitor(CONFIG_FILE)
    mode = monitor.config.get('monitoring_mode', 'continuous')
    
    if mode == 'single':
        monitor.scan_processes()
    else:
        interval = monitor.config.get('scan_interval', 60)
        monitor.run_continuous_monitoring(interval)
if __name__ == "__main__":
    main()