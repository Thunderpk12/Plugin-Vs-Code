"""
A04:2025 - Cryptographic Failures Analyzer
Deteta falhas criptográficas e gestão inadequada de dados sensíveis
"""

import ast
import re
from typing import List, Set
from models import Vulnerability

class CryptoAnalyzer(ast.NodeVisitor):
    """
    Analisa falhas criptográficas:
    - Algoritmos de hash fracos (MD5, SHA1)
    - Cifras obsoletas (DES, RC4)
    - Ausência de salt em passwords
    - Chaves de cifra hardcoded
    - Transmissão de dados sensíveis sem encriptação
    - Random numbers inseguros para criptografia
    """
    
    def __init__(self):
        self.problems: List[Vulnerability] = []
        self.current_line = 0
        
        # Algoritmos fracos
        self.weak_hash_algorithms = {
            'md5', 'MD5', 'sha1', 'SHA1', 'sha', 'SHA'
        }
        
        self.weak_ciphers = {
            'DES', 'des', 'RC4', 'rc4', 'RC2', 'rc2', 'Blowfish', 'blowfish'
        }
        
        # Padrões de dados sensíveis
        self.sensitive_patterns = [
            r'password', r'passwd', r'pwd', r'secret', r'token',
            r'api[_-]?key', r'private[_-]?key', r'credit[_-]?card',
            r'ssn', r'social[_-]?security'
        ]
        
        # Funções de random inseguras
        self.insecure_random = {'random', 'randint', 'choice', 'shuffle'}
        
    def visit_Call(self, node: ast.Call) -> None:
        """Deteta chamadas a funções criptográficas inseguras"""
        self.current_line = node.lineno
        func_name = self._get_func_name(node.func)
        
        # 1. Algoritmos de hash fracos
        if any(weak in func_name for weak in self.weak_hash_algorithms):
            self.problems.append(Vulnerability(
                line=node.lineno,
                column=node.col_offset,
                type="Weak Hash Algorithm",
                function=func_name,
                pattern=f"{func_name}()",
                description=f"Using weak hash algorithm '{func_name}'. "
                           f"Use SHA-256 or bcrypt instead.",
                severity="HIGH",
                confidence="HIGH",
                category="A04"
            ))
        
        # 2. Cifras fracas/obsoletas
        if any(cipher in func_name for cipher in self.weak_ciphers):
            self.problems.append(Vulnerability(
                line=node.lineno,
                column=node.col_offset,
                type="Weak Cipher Algorithm",
                function=func_name,
                pattern=f"{func_name}",
                description=f"Using obsolete cipher '{func_name}'. "
                           f"Use AES-256-GCM or ChaCha20-Poly1305.",
                severity="HIGH",
                confidence="HIGH",
                category="A04"
            ))
        
        # 3. Password hashing sem salt (hashlib direto)
        if 'hashlib' in func_name and any(h in func_name for h in ['md5', 'sha1', 'sha256']):
            if node.args:
                try:
                    arg_source = ast.unparse(node.args[0])
                    if any(re.search(pattern, arg_source, re.IGNORECASE) 
                          for pattern in self.sensitive_patterns):
                        self.problems.append(Vulnerability(
                            line=node.lineno,
                            column=node.col_offset,
                            type="Password Hashed Without Salt",
                            function=func_name,
                            pattern=f"{func_name}(password)",
                            description="Password is hashed without salt. "
                                       "Use bcrypt, scrypt, or argon2 instead.",
                            severity="HIGH",
                            confidence="MEDIUM",
                            category="A04"
                        ))
                except:
                    pass
        
        # 4. Random inseguro para criptografia
        if any(rand in func_name for rand in self.insecure_random):
            if self._is_crypto_context(node):
                self.problems.append(Vulnerability(
                    line=node.lineno,
                    column=node.col_offset,
                    type="Insecure Random for Cryptography",
                    function=func_name,
                    pattern=f"random.{func_name}()",
                    description=f"Using insecure random.{func_name}() for security purposes. "
                               f"Use secrets module instead.",
                    severity="HIGH",
                    confidence="MEDIUM",
                    category="A04"
                ))
        
        # 5. Modo ECB inseguro
        try:
            if 'MODE_ECB' in ast.unparse(node):
                self.problems.append(Vulnerability(
                    line=node.lineno,
                    column=node.col_offset,
                    type="Insecure ECB Mode",
                    function=func_name,
                    pattern="AES.new(key, AES.MODE_ECB)",
                    description="ECB mode is insecure (leaks patterns). "
                               "Use CBC, GCM, or CTR modes.",
                    severity="HIGH",
                    confidence="HIGH",
                    category="A04"
                ))
        except:
            pass
        
        # 6. SSL/TLS versão antiga
        if 'SSLContext' in func_name or 'ssl.wrap_socket' in func_name:
            for keyword in node.keywords:
                if keyword.arg == 'ssl_version':
                    try:
                        version_str = ast.unparse(keyword.value)
                        if any(old in version_str for old in ['SSLv2', 'SSLv3', 'TLSv1', 'TLS_1_0', 'TLS_1_1']):
                            self.problems.append(Vulnerability(
                                line=node.lineno,
                                column=node.col_offset,
                                type="Outdated TLS Version",
                                function=func_name,
                                pattern=f"ssl_version={version_str}",
                                description=f"Using outdated {version_str}. "
                                           f"Use TLS 1.2 or 1.3.",
                                severity="HIGH",
                                confidence="HIGH",
                                category="A04"
                            ))
                    except:
                        pass
        
        self.generic_visit(node)
    
    def visit_Assign(self, node: ast.Assign) -> None:
        """Deteta chaves criptográficas hardcoded"""
        self.current_line = node.lineno
        
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                
                # Chave criptográfica hardcoded
                if any(pattern in var_name.lower() for pattern in ['key', 'secret', 'cipher']):
                    if isinstance(node.value, ast.Constant):
                        if isinstance(node.value.value, (str, bytes)):
                            self.problems.append(Vulnerability(
                                line=node.lineno,
                                column=node.col_offset,
                                type="Hardcoded Cryptographic Key",
                                function=var_name,
                                pattern=f"{var_name} = 'literal'",
                                description=f"Cryptographic key '{var_name}' is hardcoded. "
                                           f"Use key derivation or secure storage.",
                                severity="HIGH",
                                confidence="HIGH",
                                category="A04"
                            ))
        
        self.generic_visit(node)
    
    def visit_Import(self, node: ast.Import) -> None:
        """Deteta imports de bibliotecas criptográficas obsoletas"""
        for alias in node.names:
            if alias.name in ['pycrypto', 'crypto']:
                self.problems.append(Vulnerability(
                    line=node.lineno,
                    column=node.col_offset,
                    type="Deprecated Crypto Library",
                    function=alias.name,
                    pattern=f"import {alias.name}",
                    description=f"Library '{alias.name}' is deprecated and insecure. "
                               f"Use 'cryptography' or 'pycryptodome' instead.",
                    severity="MEDIUM",
                    confidence="HIGH",
                    category="A04"
                ))
        
        self.generic_visit(node)
    
    def _get_func_name(self, func_node: ast.AST) -> str:
        """Extrai o nome completo de uma função"""
        if isinstance(func_node, ast.Name):
            return func_node.id
        elif isinstance(func_node, ast.Attribute):
            base = self._get_func_name(func_node.value)
            return f"{base}.{func_node.attr}" if base else func_node.attr
        return ""
    
    def _is_crypto_context(self, node: ast.Call) -> bool:
        """
        Heurística: verifica se o random está sendo usado em contexto criptográfico
        """
        try:
            parent_line = ast.unparse(node)
            return any(pattern in parent_line.lower() 
                      for pattern in ['token', 'key', 'secret', 'nonce', 'salt', 'iv'])
        except:
            return False
