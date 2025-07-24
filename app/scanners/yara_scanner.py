import yara
import os
from flask import current_app

class YaraScanner:
    def __init__(self):
        self.rules = None
        self.rule_count = 0
        self._load_rules()

    def _load_rules(self):
        """Robust YARA rule loading with accurate counting"""
        try:
            rules_path = os.path.join(current_app.config['YARA_RULES_DIR'], 'yara-rules-full.yar')
            if os.path.exists(rules_path):
                # First count total rules in file
                with open(rules_path, 'r', encoding='utf-8') as f:
                    total_file_rules = sum(1 for line in f if line.strip().startswith('rule '))
                
                # Compile rules with error reporting
                self.rules = yara.compile(
                    filepath=rules_path,
                    error_on_warning=False  # Changed to avoid namespace error
                )
                
                # Accurate rule counting
                self.rule_count = len([r for r in self.rules])  # Safe way to count
                
                current_app.logger.info(
                    f"YARA rules loaded: {self.rule_count}/{total_file_rules} rules processed. "
                    f"Difference of {total_file_rules - self.rule_count} rules filtered."
                )
                
            else:
                current_app.logger.error("YARA rules file not found at %s", rules_path)
                
        except yara.SyntaxError as e:
            current_app.logger.error(f"YARA syntax error in rules: {str(e)}")
        except Exception as e:
            current_app.logger.error(f"YARA loading failed: {str(e)}")

    def scan_file(self, filepath):
        """Reliable scanning with proper error handling"""
        if not self.rules:
            return {'error': 'YARA rules not loaded', 'status': 'failed', 'rules_loaded': 0}
        
        try:
            matches = self.rules.match(
                filepath,
                timeout=120,
                externals={'filename': os.path.basename(filepath)}
            )
            
            return {
                'status': 'completed',
                'matches': [{
                    'rule': match.rule,
                    'tags': list(match.tags),
                    'meta': dict(match.meta),
                    'strings': [str(s) for s in match.strings]
                } for match in matches],
                'malicious': len(matches) > 0,
                'rules_loaded': self.rule_count
            }
            
        except yara.TimeoutError:
            return {'error': 'YARA scan timed out', 'status': 'failed', 'rules_loaded': self.rule_count}
        except Exception as e:
            return {'error': f"Scan failed: {str(e)}", 'status': 'failed', 'rules_loaded': self.rule_count}