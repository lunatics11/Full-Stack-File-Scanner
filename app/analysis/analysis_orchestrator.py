import time
import os
import hashlib
import logging
from functools import partial
import shutil

logger = logging.getLogger(__name__)

def calculate_hashes(filepath):
    """Calculate MD5, SHA1, and SHA256 hashes"""
    hash_funcs = {
        'md5': hashlib.md5(),
        'sha1': hashlib.sha1(),
        'sha256': hashlib.sha256()
    }
    
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                for h in hash_funcs.values():
                    h.update(chunk)
        return {name: h.hexdigest() for name, h in hash_funcs.items()}
    except Exception as e:
        logger.error(f"Hash calculation failed: {str(e)}")
        return {name: 'error' for name in hash_funcs.keys()}

def analyze_file(filepath, progress_callback):
    """Comprehensive analysis using all tools"""
    start_time = time.time()
    results = {
        'basic_info': {
            'filename': os.path.basename(filepath),
            'file_size': os.path.getsize(filepath),
            'hashes': calculate_hashes(filepath)
        },
        'upx': {'packed': False, 'unpacked': False, 'error': None},
        'exiftool': {'error': None, 'data': {}},
        'peframe': {'error': None, 'data': {}},
        'radare2': {'error': None, 'data': {}},
        'readpe': {'error': None, 'output': ''},
        'strings': {'error': None, 'count': 0, 'interesting': [], 'strings': []},
        'scanners': {
            'virustotal': {'error': None, 'positives': 0, 'total': 0, 'permalink': ''},
            'yara': {'error': None, 'matches': [], 'rules_loaded': 0},
            'is_malicious': False
        },
        'analysis_time': 0,
        'warnings': []
    }

    try:
        update_progress = partial(progress_callback, filepath=filepath)

        # Stage 1: Initial analysis (0-20%)
        update_progress(5, 'Initializing analysis')
        update_progress(10, 'Calculating hashes')

        if shutil.which("upx"):
            update_progress(20, 'Checking for UPX packing')
            from .upx_unpacker import unpack_if_upx
            upx_result = unpack_if_upx(filepath)
        else:
            upx_result = {
                'packed': False,
                'unpacked': False,
                'error': 'Unavailable in demo deployment'
            }

        print("\n========== UPX RESULT ==========")
        print(upx_result)
        print("================================\n")

        results['upx'].update(upx_result)

        scan_target = upx_result.get('unpacked_path', filepath)

        print(f"SCAN TARGET: {scan_target}")

        # Stage 3: Basic analysis (30-60%)
        if shutil.which("exiftool"):
            update_progress(30, 'Running exiftool analysis')
            from .exiftool_analyzer import exiftool_analysis
            results['exiftool']['data'] = exiftool_analysis(scan_target)
        else:
            results['exiftool'] = {
                'error': 'Unavailable in demo deployment',
                'data': {}
            }

        if shutil.which("peframe"):
            update_progress(40, 'Running PEframe analysis')
            from .peframe_analyzer import peframe_analysis
            results['peframe']['data'] = peframe_analysis(scan_target)
        else:
            results['peframe'] = {
                'error': 'Unavailable in demo deployment',
                'data': {}
            }
            

        if shutil.which("r2"):
            update_progress(50, 'Running radare2 analysis')
            from .radare2_analyzer import radare2_analysis
            results['radare2']['data'] = radare2_analysis(scan_target)
        else:
            results['radare2'] = {
                'error': 'Unavailable in demo deployment',
                'data': {}
            }

        update_progress(55, 'Running readpe analysis')
        from .readpe_analyzer import readpe_analysis
        results['readpe']['output'] = readpe_analysis(scan_target)

        update_progress(60, 'Extracting strings')

        from app.analysis.ioc_analyzer import analyze_iocs
        from .strings_analyzer import strings_analysis
        strings_result = strings_analysis(scan_target)
        results['strings'].update(strings_result)
        ioc_results = analyze_iocs(
            results["strings"].get("strings", [])
        )

        results["iocs"] = ioc_results

        # Stage 4: Security scanning (60-90%)
        update_progress(70, 'Running YARA scan')
        from .scanning import scan_yara
        yara_results = scan_yara(scan_target)
        results['scanners']['yara'].update(yara_results)

        
        update_progress(85, 'Running VirusTotal scan')
        from .scanning import scan_virustotal
        vt_results = scan_virustotal(scan_target)
        results['scanners']['virustotal'].update(vt_results)

        # Determine malicious status
        results['scanners']['is_malicious'] = vt_results.get('positives', 0) > 0 or bool(yara_results.get('matches', []))

        # Threat assessment

        vt_hits = vt_results.get('positives', 0)
        yara_hits = len(yara_results.get('matches', []))

        score = 0

        score += min(vt_hits * 2, 70)

        if yara_hits > 0:
            score += 20

        ioc_count = results["iocs"]["total"]

        score += min(ioc_count * 5, 20)

        results['threat_assessment'] = {
            'score': min(score, 100),
            'classification': 'Unknown',
            'risk_level': 'Low',
            'confidence': 'Low'
        }
        

        detections_text = str(vt_results).lower()

        if any(x in detections_text for x in [
            'downloader',
            'fragtor'
        ]):
            classification = 'Downloader Trojan'

        elif any(x in detections_text for x in [
            'ransom',
            'crypt'
        ]):
            classification = 'Ransomware'

        elif any(x in detections_text for x in [
            'backdoor'
        ]):
            classification = 'Backdoor'

        else:
            if vt_hits == 0 and yara_hits == 0:
                classification = "Benign File"
            else:
                classification = "Generic Malware"

        results['threat_assessment']['classification'] = classification

        score = results['threat_assessment']['score']

        if score == 0:
            risk = 'Safe'
        elif score >= 90:
            risk = 'Critical'
        elif score >= 70:
            risk = 'High'
        elif score >= 40:
            risk = 'Medium'
        else:
            risk = 'Low'

        results['threat_assessment']['risk_level'] = risk

        if vt_hits == 0:
            confidence = 'High'
        elif vt_hits > 40:
            confidence = 'High'
        elif vt_hits > 10:
            confidence = 'Medium'
        else:
            confidence = 'Low'

        results['threat_assessment']['confidence'] = confidence

    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")
        results['error'] = str(e)
    finally:
        results['analysis_time'] = time.time() - start_time
        update_progress(100, 'Analysis complete')
        
        # Cleanup unpacked file if exists
        if 'unpacked_path' in results['upx']:
            try:
                os.remove(results['upx']['unpacked_path'])
            except Exception as e:
                logger.error(f"Cleanup failed: {str(e)}")

    if 'threat_assessment' not in results:
        results['threat_assessment'] = {
            'score': 0,
            'risk_level': 'Safe',
            'confidence': 'High',
            'classification': 'Benign File'
        }
    return results