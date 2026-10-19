import os
import re

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print("[YARA] Warning: yara-python not installed. Using pure Python fallback scanner.")

class YaraScanner:
    def __init__(self, rules_path="rules/main.yar"):
        """
        Initialize the YARA scanner. If yara-python is not available,
        it uses a lightweight pure Python fallback for the default rules.
        """
        self.rules_path = rules_path
        self.rules = None
        self.fallback_rules = []

        abs_rules_path = os.path.abspath(rules_path)
        print(f"[YARA] Looking for rules at: {abs_rules_path}")

        if not os.path.exists(abs_rules_path):
            print(f"[YARA] Rules file not found at {abs_rules_path}")
            return

        if YARA_AVAILABLE:
            try:
                self.rules = yara.compile(filepath=abs_rules_path)
                print(f"[YARA] Successfully compiled rules from {abs_rules_path}")
            except Exception as e:
                print(f"[YARA] Error compiling rules: {e}")
        else:
            self._load_fallback_rules(abs_rules_path)

    def _load_fallback_rules(self, filepath):
        """
        A lightweight parser for basic YARA rules to use when yara-python is missing.
        It parses rule name, score from meta, and simple strings/hex strings.
        """
        try:
            with open(filepath, 'r') as f:
                content = f.read()
            
            # Find all rule names
            rule_names = re.findall(r'rule\s+(\w+)', content)
            
            # Split content by 'rule ' to get individual rule blocks
            blocks = content.split('rule ')[1:]
            
            for block in blocks:
                # Extract rule name
                rule_name_m = re.match(r'(\w+)', block)
                if not rule_name_m:
                    continue
                rule_name = rule_name_m.group(1)
                
                rule = {
                    "name": rule_name,
                    "score": 50,
                    "description": "No description",
                    "strings": []
                }
                
                # Extract meta
                meta_match = re.search(r'meta:(.*?)strings:', block, re.IGNORECASE | re.DOTALL)
                if meta_match:
                    meta_block = meta_match.group(1)
                    score_m = re.search(r'score\s*=\s*(\d+)', meta_block)
                    desc_m = re.search(r'description\s*=\s*"([^"]+)"', meta_block)
                    if score_m: rule["score"] = int(score_m.group(1))
                    if desc_m: rule["description"] = desc_m.group(1)
                
                # Extract strings
                strings_match = re.search(r'strings:(.*?)condition:', block, re.IGNORECASE | re.DOTALL)
                if strings_match:
                    strings_block = strings_match.group(1)
                    # Text strings
                    for name, val in re.findall(r'(\$\w+)\s*=\s*"([^"]+)"', strings_block):
                        rule["strings"].append({"name": name, "type": "text", "val": val.encode('utf-8')})
                    # Hex strings
                    for name, val in re.findall(r'(\$\w+)\s*=\s*\{([^}]+)\}', strings_block):
                        hex_str = val.replace(' ', '').replace('\n', '')
                        hex_str = re.sub(r'//.*', '', hex_str)
                        if '?' not in hex_str and '[' not in hex_str:
                            try:
                                rule["strings"].append({"name": name, "type": "hex", "val": bytes.fromhex(hex_str)})
                            except ValueError:
                                pass
                
                # Extract condition
                condition_match = re.search(r'condition:(.*?)$', block, re.IGNORECASE | re.DOTALL)
                if condition_match:
                    rule["condition"] = condition_match.group(1).replace('}', '').strip()
                
                self.fallback_rules.append(rule)
            print(f"[YARA] Loaded {len(self.fallback_rules)} fallback rules.")
        except Exception as e:
            print(f"[YARA] Failed to load fallback rules: {e}")

    def scan_file(self, filepath):
        """
        Scan a file using compiled YARA rules or fallback scanner.
        Returns a dict with 'score', 'matches' (list of strings), and 'details' (list of strings).
        """
        if not os.path.exists(filepath):
            return {"error": "File does not exist"}

        if YARA_AVAILABLE and self.rules:
            try:
                matches = self.rules.match(filepath)
                return self._process_matches([{
                    "rule": m.rule,
                    "score": m.meta.get('score', 50),
                    "description": m.meta.get('description', 'No description')
                } for m in matches])
            except Exception as e:
                return {"error": f"YARA scanning failed: {e}"}
        
        # Fallback pure-python scanning
        if not self.fallback_rules:
            return {"error": "YARA rules not loaded"}
            
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
                
            matches = []
            for rule in self.fallback_rules:
                str_matches = {}
                for s in rule["strings"]:
                    name = s["name"]
                    str_matches[name] = s["val"] in data
                    if name + " at 0" in rule.get("condition", ""):
                        str_matches[name + " at 0"] = data.startswith(s["val"])
                
                cond = rule.get("condition", "")
                if not cond:
                    matched = any(str_matches.values()) if str_matches else False
                else:
                    eval_str = cond
                    # Sort keys by length descending to replace longest variable names first
                    for name in sorted(str_matches.keys(), key=len, reverse=True):
                        eval_str = eval_str.replace(name, str(str_matches[name]))
                    
                    try:
                        matched = eval(eval_str)
                    except Exception:
                        matched = any(str_matches.values())

                if matched:
                    matches.append({
                        "rule": rule["name"],
                        "score": rule["score"],
                        "description": rule["description"]
                    })
                    
            return self._process_matches(matches)
            
        except Exception as e:
            return {"error": f"Fallback YARA scanning failed: {e}"}

    def _process_matches(self, matches):
        total_score = 0
        details = []
        match_names = []
        
        for m in matches:
            total_score += m["score"]
            match_names.append(m["rule"])
            details.append(f"[{m['rule']}] {m['description']} (+{m['score']} risk)")

        final_score = min(total_score, 100)

        return {
            "score": final_score,
            "matches": match_names,
            "details": details
        }
