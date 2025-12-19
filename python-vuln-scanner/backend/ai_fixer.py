import requests 
import json
import re

class AIFixer:
    def __init__(self, model="deepseek-coder", base_url="http://localhost:11434"):
        self.model = model
        self.url = f"{base_url}/api/generate"

    def get_fix(self, code_snippet: str, vuln_info: str) -> str:
        # Prompt ultra-restrito focado em substituição de linha única
        prompt = f"""
        [STRICT INSTRUCTION]
        You are a surgical code replacement tool. 
        Your task is to fix the security issue in ONE specific Python line.
        
        RULES:
        1. DO NOT add imports.
        2. DO NOT add decorators (@login_required, etc.).
        3. DO NOT explain anything.
        4. USE the same variable names.
        5. RETURN ONLY THE CORRECTED LINE OF CODE.
        
        Vulnerability: {vuln_info}
        Vulnerable line: {code_snippet}
        
        Fixed line:
        """

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.0,
                "stop": ["Vulnerable line:", "Fixed line:", "[STRICT"]
            }
        }

        try:
            response = requests.post(self.url, json=payload, timeout=30)
            response.raise_for_status()
            raw_response = response.json().get('response', '').strip()

            # --- Limpeza de Emergência ---
            # Remove blocos markdown se a IA ignorar as regras
            if "```" in raw_response:
                raw_response = re.findall(r"```(?:python)?\s*(.*?)\s*```", raw_response, re.DOTALL)[0]
            
            # Pega apenas a primeira linha útil (evita comentários e alucinações posteriores)
            lines = [l for l in raw_response.split('\n') if l.strip() and not l.strip().startswith(('#', 'Sure', 'Here'))]
            
            return lines[0].strip() if lines else raw_response.strip()

        except Exception as e:
            return f"# AI Error: {str(e)}"