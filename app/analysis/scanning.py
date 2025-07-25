import os
import requests
import yara
import logging
import hashlib
import time
from time import sleep
from flask import current_app
from pathlib import Path

logger = logging.getLogger(__name__)

# Global YARA state
_yara_rules = None
_yara_rule_count = 0
_yara_initialized = False

def _load_yara_rules():
    """Completely robust YARA rule loader with detailed error reporting"""
    global _yara_rules, _yara_rule_count, _yara_initialized
    
    rules_path = current_app.config.get('YARA_RULES_PATH')
    if not rules_path:
        logger.error("YARA_RULES_PATH not configured")
        return False
    
    rules_path = Path(rules_path).absolute()
    if not rules_path.exists():
        logger.error(f"YARA rules file not found at {rules_path}")
        return False

    try:
        # Try loading as compiled rules first
        try:
            _yara_rules = yara.load(str(rules_path))
            logger.info("Loaded pre-compiled YARA rules")
        except yara.Error:
            # Fall back to compiling from source
            _yara_rules = yara.compile(
                filepath=str(rules_path),
                error_on_warning=True,
                includes=True
            )
            logger.info("Compiled YARA rules from source")

        # Verify and count rules
        if _yara_rules is None:
            logger.error("YARA rules loaded as None")
            return False
            
        _yara_rule_count = sum(1 for _ in _yara_rules)
        logger.info(f"Successfully loaded {_yara_rule_count} YARA rules from {rules_path}")
        
        # Debug namespace distribution
        namespaces = {}
        for rule in _yara_rules:
            namespaces[rule.namespace] = namespaces.get(rule.namespace, 0) + 1
        for ns, count in namespaces.items():
            logger.debug(f"Namespace '{ns}': {count} rules")
        
        _yara_initialized = True
        return True
        
    except yara.SyntaxError as e:
        logger.error(f"YARA syntax error at line {e.line}: {e.message}")
    except yara.Error as e:
        logger.error(f"YARA error: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
    
    _yara_initialized = False
    return False

def scan_yara(filepath):
    """Perform YARA scan with all loaded rules"""
    try:
        # Initialize scanner if not already done
        if 'yara_scanner' not in current_app.extensions:
            from app.scanners.yara_scanner import YaraScanner
            current_app.extensions['yara_scanner'] = YaraScanner()
        
        scanner = current_app.extensions['yara_scanner']
        return scanner.scan_file(filepath)
        
    except Exception as e:
        return {
            'error': f"YARA scan initialization failed: {str(e)}",
            'status': 'failed',
            'rules_loaded': 0
        }


def scan_virustotal(filepath):
    """Simplified and reliable VirusTotal scanning"""
    if not current_app.config.get('VT_API_KEY'):
        return {'error': 'API key not configured'}

    # First try to get existing report
    try:
        with open(filepath, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        
        report_url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        report_response = requests.get(
            report_url,
            headers={'x-apikey': current_app.config['VT_API_KEY']},
            timeout=30
        )
        
        if report_response.status_code == 200:
            data = report_response.json().get('data', {}).get('attributes', {})
            return {
                'positives': data.get('last_analysis_stats', {}).get('malicious', 0),
                'total': sum(data.get('last_analysis_stats', {}).values()),
                'permalink': data.get('permalink', ''),
                'scans': {
                    scanner: {
                        'detected': result['category'] == 'malicious',
                        'result': result.get('result', ''),
                        'version': result.get('engine_version', '')
                    }
                    for scanner, result in data.get('last_analysis_results', {}).items()
                }
            }
    except Exception as e:
        current_app.logger.error(f"VT report check failed: {str(e)}")

    # If no existing report, upload the file
    try:
        with open(filepath, 'rb') as f:
            response = requests.post(
                'https://www.virustotal.com/api/v3/files',
                headers={'x-apikey': current_app.config['VT_API_KEY']},
                files={'file': f},
                timeout=60
            )

        if response.status_code != 200:
            return {'error': f"Upload failed ({response.status_code})"}

        analysis_id = response.json()['data']['id']
        permalink = f"https://www.virustotal.com/gui/file/{analysis_id}"

        # Wait for analysis to complete (simple version)
        time.sleep(15)
        report = requests.get(
            f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
            headers={'x-apikey': current_app.config['VT_API_KEY']},
            timeout=30
        )

        if report.status_code == 200:
            data = report.json().get('data', {}).get('attributes', {})
            stats = data.get('stats', {})
            return {
                'positives': stats.get('malicious', 0),
                'total': sum(stats.values()),
                'permalink': permalink,
                'scans': {
                    k: {
                        'detected': v['category'] == 'malicious',
                        'result': v.get('result', ''),
                        'version': v.get('engine_version', '')
                    }
                    for k, v in data.get('results', {}).items()
                }
            }
        return {'error': 'Analysis not ready', 'permalink': permalink}

    except Exception as e:
        return {'error': f"Scan failed: {str(e)}"}
    
def send_to_scanners(filepath):
    """Main scanning coordination function"""
    results = {
        'virustotal': {'error': 'Not scanned yet'},
        'yara': {'error': 'Not scanned yet'},
        'is_malicious': False
    }

    # Run YARA scan first
    yara_results = scan_yara(filepath)
    results['yara'] = yara_results
    results['is_malicious'] = bool(yara_results.get('matches', []))

    # Run VirusTotal scan
    vt_results = scan_virustotal(filepath)
    if isinstance(vt_results, dict):
        results['virustotal'] = vt_results
        results['is_malicious'] = results['is_malicious'] or vt_results.get('positives', 0) > 0

    return results