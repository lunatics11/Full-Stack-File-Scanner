import yara
import os
from flask import current_app


class YaraScanner:
    def __init__(self):
        self.rules = None
        self.rule_count = 0
        self._load_rules()

    def _load_rules(self):
        """Load YARA rules and report useful diagnostics"""

        try:
            rules_path = os.path.join(
                current_app.config['YARA_RULES_DIR'],
                'yara-rules-full.yar'
            )

            current_app.logger.info(
                f"[YARA] Looking for rules at: {rules_path}"
            )

            if not os.path.exists(rules_path):
                current_app.logger.error(
                    f"[YARA] Rules file not found: {rules_path}"
                )
                return

            # Count rules in source file
            total_file_rules = 0

            try:
                with open(rules_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if line.strip().startswith("rule "):
                            total_file_rules += 1
            except Exception as e:
                current_app.logger.warning(
                    f"[YARA] Could not count rules: {e}"
                )

            current_app.logger.info(
                f"[YARA] Source file contains approximately "
                f"{total_file_rules} rules"
            )

            # Compile rules
            self.rules = yara.compile(
                filepath=rules_path,
                error_on_warning=False
            )

            # Count compiled rules
            try:
                self.rule_count = len([r for r in self.rules])
            except Exception:
                self.rule_count = total_file_rules

            current_app.logger.info(
                f"[YARA] Successfully loaded "
                f"{self.rule_count} rules"
            )

        except yara.SyntaxError as e:
            current_app.logger.error(
                f"[YARA] Syntax error: {e}"
            )

        except Exception as e:
            current_app.logger.exception(
                f"[YARA] Failed to load rules: {e}"
            )

    def scan_file(self, filepath):
        """Scan a file using loaded YARA rules"""

        if not self.rules:
            return {
                "status": "failed",
                "error": "YARA rules not loaded",
                "rules_loaded": 0
            }

        if not os.path.exists(filepath):
            return {
                "status": "failed",
                "error": f"File not found: {filepath}",
                "rules_loaded": self.rule_count
            }

        try:
            current_app.logger.info(
                f"[YARA] Scanning file: {filepath}"
            )

            matches = self.rules.match(
                filepath,
                timeout=120
            )

            current_app.logger.info(
                f"[YARA] Match count: {len(matches)}"
            )

            parsed_matches = []

            for match in matches:
                parsed_matches.append({
                    "rule": match.rule,
                    "tags": list(match.tags),
                    "meta": dict(match.meta)
                })

            return {
                "status": "completed",
                "malicious": len(matches) > 0,
                "match_count": len(matches),
                "rules_loaded": self.rule_count,
                "matches": parsed_matches
            }

        except yara.TimeoutError:
            current_app.logger.error(
                f"[YARA] Scan timeout for {filepath}"
            )

            return {
                "status": "failed",
                "error": "YARA scan timed out",
                "rules_loaded": self.rule_count
            }

        except Exception as e:
            current_app.logger.exception(
                f"[YARA] Scan failed: {e}"
            )

            return {
                "status": "failed",
                "error": str(e),
                "rules_loaded": self.rule_count
            }