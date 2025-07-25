import requests
import time
import hashlib
import logging
from flask import current_app
from pathlib import Path

logger = logging.getLogger(__name__)

class VirusTotalScanner:
    def __init__(self):
        self.api_key = current_app.config['VT_API_KEY']
        self.base_url = "https://www.virustotal.com/api/v3"
        self.timeout = 60
        self.last_request = 0
        self.request_interval = 15  # seconds between requests

    def scan_file(self, filepath):
        """Complete scanning workflow with enhanced error handling"""
        try:
            # Validate file
            validation = self._validate_file(filepath)
            if validation.get('error'):
                return validation

            # Enforce rate limiting
            self._wait_for_rate_limit()

            # Check existing report first
            existing = self._get_existing_report(validation['sha256'])
            if existing:
                return existing

            # If not found, upload and analyze
            upload_result = self._upload_file(filepath)
            if upload_result.get('error'):
                return upload_result

            # Get analysis with proper timeout handling
            analysis_result = self._get_analysis(upload_result['id'])
            if analysis_result.get('error'):
                return analysis_result

            return analysis_result

        except requests.exceptions.Timeout:
            return {
                'error': 'VirusTotal request timed out',
                'status': 'failed',
                'timestamp': int(time.time())
            }
        except requests.exceptions.RequestException as e:
            return {
                'error': f'VirusTotal connection error: {str(e)}',
                'status': 'failed',
                'timestamp': int(time.time())
            }
        except Exception as e:
            logger.error(f"Unexpected error in VirusTotal scan: {str(e)}")
            return {
                'error': f'Analysis failed: {str(e)}',
                'status': 'failed',
                'timestamp': int(time.time())
            }

    def _validate_file(self, filepath):
        """Validate file before scanning"""
        try:
            path = Path(filepath)
            if not path.exists():
                return {'error': 'File not found', 'status': 'failed'}
            
            size = path.stat().st_size
            if size > 32 * 1024 * 1024:  # 32MB limit
                return {'error': 'File exceeds size limit (32MB)', 'status': 'failed'}

            with open(filepath, 'rb') as f:
                sha256 = hashlib.sha256(f.read()).hexdigest()

            return {
                'sha256': sha256,
                'size': size,
                'status': 'validated'
            }
        except Exception as e:
            return {'error': f'Validation failed: {str(e)}', 'status': 'failed'}

    def _wait_for_rate_limit(self):
        """Enforce minimum time between requests"""
        elapsed = time.time() - self.last_request
        if elapsed < self.request_interval:
            time.sleep(self.request_interval - elapsed)
        self.last_request = time.time()

    def _get_existing_report(self, file_hash):
        """Check for existing analysis with proper error handling"""
        try:
            response = requests.get(
                f"{self.base_url}/files/{file_hash}",
                headers={'x-apikey': self.api_key},
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                stats = data.get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'positives': stats.get('malicious', 0),
                    'total': sum(stats.values()),
                    'permalink': f"https://www.virustotal.com/gui/file/{file_hash}",
                    'status': 'completed',
                    'source': 'existing',
                    'response_code': 1
                }
            elif response.status_code == 404:
                return None  # File not found in VT
            else:
                error_msg = f"VirusTotal API error: {response.status_code}"
                try:
                    error_data = response.json().get('error', {})
                    error_msg = f"{error_data.get('code')}: {error_data.get('message')}"
                except:
                    error_msg = f"{error_msg}: {response.text[:200]}"
                return {'error': error_msg, 'status': 'failed'}
                
        except Exception as e:
            logger.warning(f"Existing report check failed: {str(e)}")
            return {'error': f"Report check failed: {str(e)}", 'status': 'failed'}

    def _upload_file(self, filepath):
        """Upload file for analysis with timeout handling"""
        try:
            with open(filepath, 'rb') as f:
                response = requests.post(
                    f"{self.base_url}/files",
                    headers={'x-apikey': self.api_key},
                    files={'file': f},
                    timeout=120
                )
            
            if response.status_code == 200:
                return {
                    'id': response.json().get('data', {}).get('id'),
                    'status': 'queued'
                }
            
            error = f"Upload failed ({response.status_code})"
            try:
                error_data = response.json().get('error', {})
                error = f"{error_data.get('code')}: {error_data.get('message')}"
            except:
                error = f"{error}: {response.text[:200]}"
            
            return {'error': error, 'status': 'failed'}

        except Exception as e:
            return {'error': f"Upload error: {str(e)}", 'status': 'failed'}

    def _get_analysis(self, analysis_id):
        """Poll for analysis results with proper timeout handling"""
        max_attempts = 10
        initial_delay = 15
        max_delay = 60
        
        for attempt in range(max_attempts):
            try:
                current_delay = min(initial_delay * (attempt + 1), max_delay)
                time.sleep(current_delay)
                
                response = requests.get(
                    f"{self.base_url}/analyses/{analysis_id}",
                    headers={'x-apikey': self.api_key},
                    timeout=30
                )
                
                data = response.json().get('data', {})
                status = data.get('attributes', {}).get('status')

                if status == 'completed':
                    stats = data.get('attributes', {}).get('stats', {})
                    return {
                        'positives': stats.get('malicious', 0),
                        'total': sum(stats.values()),
                        'permalink': data.get('links', {}).get('item'),
                        'status': 'completed',
                        'source': 'new_scan',
                        'response_code': 1,
                        'scans': {
                            scanner: {
                                'detected': result['category'] == 'malicious',
                                'result': result.get('result', ''),
                                'version': result.get('engine_version', '')
                            }
                            for scanner, result in data.get('attributes', {}).get('results', {}).items()
                        }
                    }
                elif status in ['queued', 'in-progress']:
                    continue
                else:
                    return {'error': f"Analysis failed with status: {status}", 'status': 'failed'}
            
            except requests.exceptions.Timeout:
                if attempt == max_attempts - 1:
                    return {'error': 'Analysis polling timed out', 'status': 'failed'}
                continue
            except Exception as e:
                return {'error': f"Analysis error: {str(e)}", 'status': 'failed'}

        return {'error': 'Analysis timed out', 'status': 'failed'}