from .yara_scanner import YaraScanner
from .virustotal import VirusTotalScanner

# Initialize scanners with app when created
def init_scanners(app):
    yara_scanner = YaraScanner(app)
    vt_scanner = VirusTotalScanner(app)  # If you have a VT Scanner class
    
    app.extensions['yara_scanner'] = yara_scanner
    app.extensions['vt_scanner'] = vt_scanner

__all__ = ['YaraScanner', 'VirusTotalScanner', 'init_scanners']