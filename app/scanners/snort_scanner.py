import subprocess
import tempfile
import os
from pathlib import Path
import logging
from config import Config

class SnortScanner:
    def __init__(self):
        self.snort_config = getattr(Config, 'SNORT_CONFIG', '/etc/snort/snort.conf')
        self.snort_rules = getattr(Config, 'SNORT_RULES', '/etc/snort/rules')
        self.log_dir = getattr(Config, 'SNORT_LOG_DIR', '/tmp/snort_logs')
        
        # Validate paths
        self._validate_paths()

    def _validate_paths(self):
        """Ensure required Snort paths exist"""
        if not Path(self.snort_config).exists():
            raise FileNotFoundError(f"Snort config not found at {self.snort_config}")
        if not Path(self.snort_rules).exists():
            raise FileNotFoundError(f"Snort rules not found at {self.snort_rules}")
        Path(self.log_dir).mkdir(exist_ok=True)

    def scan_file(self, filepath):
        """Scan a file with Snort"""
        try:
            # Create temp alert file
            alert_file = tempfile.mktemp(dir=self.log_dir, suffix='.alert')
            
            # Build Snort command
            cmd = [
                'snort',
                '-c', self.snort_config,
                '-R', self.snort_rules,
                '-r', str(Path(filepath).absolute()),
                '-A', 'fast',
                '-l', self.log_dir,
                '--alert-file', alert_file
            ]
            
            # Run Snort
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60  # 1 minute timeout
            )
            
            # Parse results
            alerts = self._parse_alerts(alert_file)
            
            return {
                'status': 'completed',
                'alerts': alerts,
                'malicious': len(alerts) > 0,
                'snort_output': result.stdout,
                'snort_errors': result.stderr
            }
            
        except subprocess.TimeoutExpired:
            return {
                'error': 'Snort scan timed out',
                'status': 'failed'
            }
        except Exception as e:
            return {
                'error': str(e),
                'status': 'failed'
            }
        finally:
            # Clean up alert file if it exists
            if 'alert_file' in locals() and Path(alert_file).exists():
                Path(alert_file).unlink()

    def _parse_alerts(self, alert_file):
        """Parse Snort alert file"""
        alerts = []
        try:
            if Path(alert_file).exists():
                with open(alert_file, 'r') as f:
                    for line in f:
                        if line.strip() and not line.startswith('#'):
                            alerts.append(line.strip())
        except Exception as e:
            logging.error(f"Failed to parse Snort alerts: {str(e)}")
        return alerts