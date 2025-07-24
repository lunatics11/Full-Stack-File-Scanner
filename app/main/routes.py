from flask import render_template, request, current_app, jsonify, session, copy_current_request_context
from threading import Thread
import os
import uuid
import time
from app.main import main

# Global store for scan results
scan_results = {}

@main.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@main.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({"error": "No file uploaded"}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"error": "Empty filename"}), 400
        
        # Save to temp location
        temp_path = os.path.join(current_app.config['UPLOAD_FOLDER'], file.filename)
        file.save(temp_path)
        
        # Generate unique scan ID
        scan_id = str(uuid.uuid4())
        session['scan_id'] = scan_id
        
        # Initialize progress tracking
        scan_results[scan_id] = {
            'progress': 0,
            'status': 'Starting analysis',
            'complete': False,
            'results': None,
            'error': None,
            'filepath': temp_path,
            'vt_attempts': 0  # Track VirusTotal attempts
        }
        
        # Start background scan with request context
        @copy_current_request_context
        def run_scan(scan_id):
            from app.analysis.analysis_orchestrator import analyze_file
            try:
                def progress_callback(progress, status, filepath):
                    if scan_id in scan_results:
                        scan_results[scan_id]['progress'] = progress
                        scan_results[scan_id]['status'] = status
                
                # Add retry logic for VirusTotal
                max_attempts = 3
                for attempt in range(max_attempts):
                    try:
                        scan_results[scan_id]['vt_attempts'] = attempt + 1
                        scan_results[scan_id]['results'] = analyze_file(
                            scan_results[scan_id]['filepath'],
                            progress_callback
                        )
                        scan_results[scan_id]['complete'] = True
                        scan_results[scan_id]['status'] = 'Analysis complete'
                        break
                    except Exception as e:
                        if "ConflictError" in str(e) and attempt < max_attempts - 1:
                            wait_time = (attempt + 1) * 15  # Exponential backoff
                            scan_results[scan_id]['status'] = f'VirusTotal busy, retrying in {wait_time}s...'
                            time.sleep(wait_time)
                            continue
                        raise
                        
            except Exception as e:
                scan_results[scan_id]['error'] = str(e)
                scan_results[scan_id]['status'] = 'Analysis failed'
        
        Thread(target=run_scan, args=(scan_id,)).start()
        
        return render_template('upload.html', scan_started=True, scan_id=scan_id)
    
    return render_template('upload.html')

@main.route('/scan_status/<scan_id>')
def scan_status(scan_id):
    """Endpoint for progress updates"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Invalid scan ID'}), 404
    
    return jsonify({
        'progress': scan_results[scan_id]['progress'],
        'status': scan_results[scan_id]['status'],
        'complete': scan_results[scan_id]['complete'],
        'error': scan_results[scan_id]['error'],
        'attempts': scan_results[scan_id].get('vt_attempts', 1)
    })

@main.route('/results/<scan_id>')
def show_results(scan_id):
    """Display scan results"""
    if scan_id not in scan_results:
        return "Scan not found", 404
    
    if not scan_results[scan_id]['complete']:
        return "Analysis not complete", 400
    
    # Clean up file
    if os.path.exists(scan_results[scan_id]['filepath']):
        os.remove(scan_results[scan_id]['filepath'])
    
    return render_template(
        'results.html',
        results=scan_results[scan_id]['results']
    )