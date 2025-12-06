"""
Pt: A07:2021 - Identification and Authentication Failures
Eng: A07:2021 - Identification and Authentication Failures

Este analisador deteta:
- Credenciais hardcoded (passwords, API keys, tokens)
- Tokens/sessões sem expiração adequada
- Autenticação fraca (comparações inseguras, sem rate limiting)
- Exposição de informação em erros de autenticação
- Falta de proteções contra ataques de força bruta
"""

import ast
import re
from typing import List, Set, Optional, Pattern
from models import Vulnerability

class AuthenticationAnalyzer(ast.NodeVisitor):
    """
    Pt: Analisa falhas de autenticação e gestão de identidade
    Eng: Analyzes authentication and identity management failures
    """
    
    # Palavras-chave que indicam credenciais
    CREDENTIAL_KEYWORDS = {
        'password', 'passwd', 'pwd', 'pass',
        'secret', 'api_key', 'apikey', 'api_token',
        'auth_token', 'access_token', 'refresh_token',
        'private_key', 'secret_key', 'encryption_key',
        'database_password', 'db_password', 'db_passwd',
        'admin_password', 'root_password',
        'jwt_secret', 'session_secret',
        'aws_secret', 'azure_key', 'gcp_key',
        'oauth_secret', 'client_secret',
        'bearer_token', 'authorization'
    }
    
    # Funções de autenticação conhecidas
    AUTH_FUNCTIONS = {
        'authenticate', 'login', 'signin', 'sign_in',
        'verify_password', 'check_password', 'validate_password',
        'verify_credentials', 'check_credentials',
        'authorize', 'check_auth', 'verify_token',
        'validate_token', 'decode_token'
    }
    
    # Funções de sessão
    SESSION_FUNCTIONS = {
        'create_session', 'new_session', 'start_session',
        'generate_token', 'create_token', 'issue_token',
        'set_session', 'session.save', 'session.commit'
    }
    
    # Comparadores inseguros para autenticação
    UNSAFE_COMPARISONS = {'==', '!=', 'is', 'is not'}
    
    # Padrões regex para detectar valores sensíveis hardcoded
    PATTERNS = {
        'generic_secret': re.compile(r'["\']([a-zA-Z0-9_-]{20,})["\']'),
        'jwt_token': re.compile(r'["\']eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+["\']'),
        'api_key': re.compile(r'["\'][A-Z0-9]{32,}["\']'),
        'aws_key': re.compile(r'AKIA[0-9A-Z]{16}'),
        'private_key': re.compile(r'-----BEGIN (RSA |EC )?PRIVATE KEY-----'),
    }
    
    def __init__(self):
        self.problems: List[Vulnerability] = []
        self.current_function: Optional[str] = None
        self.found_credentials: Set[str] = set()
        
    def _get_full_name(self, node: ast.AST) -> str:
        """Helper para obter nome completo de um nó"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            parent = self._get_full_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""
    
    def _is_credential_variable(self, var_name: str) -> bool:
        """Verifica se nome de variável sugere credencial"""
        var_lower = var_name.lower()
        return any(keyword in var_lower for keyword in self.CREDENTIAL_KEYWORDS)
    
    def _is_suspicious_string(self, value: str) -> Optional[str]:
        """Verifica se string parece ser credencial hardcoded"""
        # Ignorar strings muito curtas ou muito comuns
        if len(value) < 8 or value.lower() in {'password', 'secret', 'token', 'key', 'admin', 'root', 'test'}:
            return None
        
        # Verificar padrões conhecidos
        for pattern_name, pattern in self.PATTERNS.items():
            if pattern.search(value):
                return pattern_name
        
        # Heurística: string longa com alta entropia
        if len(value) >= 16 and self._has_high_entropy(value):
            return 'high_entropy_string'
        
        return None
    
    def _has_high_entropy(self, s: str) -> bool:
        """Calcula se string tem alta entropia (possível secret)"""
        if not s:
            return False
        
        # Contar tipos de caracteres
        has_upper = any(c.isupper() for c in s)
        has_lower = any(c.islower() for c in s)
        has_digit = any(c.isdigit() for c in s)
        has_special = any(not c.isalnum() for c in s)
        
        # Se tem pelo menos 3 tipos diferentes, consideramos alta entropia
        char_types = sum([has_upper, has_lower, has_digit, has_special])
        return char_types >= 3
    
    def visit_Assign(self, node: ast.Assign):
        """Detecta credenciais hardcoded em atribuições"""
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                
                # Verificar se variável é credencial
                if self._is_credential_variable(var_name):
                    # Verificar se valor é hardcoded
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        string_value = node.value.value
                        
                        # Não reportar se for placeholder óbvio
                        if string_value.lower() in {'', 'none', 'null', 'todo', 'changeme', 'your_password_here'}:
                            self.generic_visit(node)
                            return
                        
                        pattern_match = self._is_suspicious_string(string_value)
                        
                        self.problems.append(Vulnerability(
                            line=node.lineno,
                            column=node.col_offset,
                            type='Hardcoded Credentials',
                            function=self.current_function or 'module level',
                            pattern=f"variable '{var_name}' with hardcoded value",
                            description=f"Variable '{var_name}' contains hardcoded credentials. Use environment variables or secret management.",
                            severity="HIGH",
                            confidence="HIGH" if pattern_match else "MEDIUM",
                            category="A07"
                        ))
                        self.found_credentials.add(var_name)
        
        self.generic_visit(node)
    
    def visit_Compare(self, node: ast.Compare):
        """Detecta comparações inseguras em autenticação"""
        # Verificar se estamos em função de autenticação
        if not self.current_function:
            self.generic_visit(node)
            return
        
        func_lower = self.current_function.lower()
        is_auth_function = any(auth in func_lower for auth in self.AUTH_FUNCTIONS)
        
        if not is_auth_function:
            self.generic_visit(node)
            return
        
        # Verificar se compara passwords/tokens
        left_name = self._get_full_name(node.left)
        
        if self._is_credential_variable(left_name):
            for op in node.ops:
                if isinstance(op, (ast.Eq, ast.NotEq, ast.Is, ast.IsNot)):
                    self.problems.append(Vulnerability(
                        line=node.lineno,
                        column=node.col_offset,
                        type='Insecure Password Comparison',
                        function=self.current_function,
                        pattern=f"using '{op.__class__.__name__}' operator",
                        description=f"Password comparison using '==' is vulnerable to timing attacks. Use secure comparison like 'secrets.compare_digest()' or 'hmac.compare_digest()'.",
                        severity="MEDIUM",
                        confidence="HIGH",
                        category="A07"
                    ))
                    break
        
        self.generic_visit(node)
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Analisa funções de autenticação"""
        old_function = self.current_function
        self.current_function = node.name
        
        func_lower = node.name.lower()
        is_auth_function = any(auth in func_lower for auth in self.AUTH_FUNCTIONS)
        is_session_function = any(sess in func_lower for sess in self.SESSION_FUNCTIONS)
        
        # Verificar funções de autenticação sem rate limiting
        if is_auth_function:
            has_rate_limit = self._check_rate_limiting(node)
            if not has_rate_limit:
                self.problems.append(Vulnerability(
                    line=node.lineno,
                    column=node.col_offset,
                    type='Missing Rate Limiting',
                    function=node.name,
                    pattern='authentication without rate limiting',
                    description=f"Authentication function '{node.name}' lacks rate limiting protection. This allows brute-force attacks.",
                    severity="MEDIUM",
                    confidence="MEDIUM",
                    category="A07"
                ))
            
            # Verificar se retorna informação diferenciada em erro
            self._check_information_disclosure(node)
        
        # Verificar funções de sessão sem expiração
        if is_session_function:
            has_expiration = self._check_session_expiration(node)
            if not has_expiration:
                self.problems.append(Vulnerability(
                    line=node.lineno,
                    column=node.col_offset,
                    type='Session Without Expiration',
                    function=node.name,
                    pattern='session creation without expiration',
                    description=f"Session/token created without expiration time. This can lead to session hijacking.",
                    severity="MEDIUM",
                    confidence="MEDIUM",
                    category="A07"
                ))
        
        self.generic_visit(node)
        self.current_function = old_function
    
    def _check_rate_limiting(self, func_node: ast.FunctionDef) -> bool:
        """Verifica se função tem rate limiting"""
        # Procurar decorators ou chamadas de rate limiting
        rate_limit_indicators = {
            'rate_limit', 'ratelimit', 'limiter', 'throttle',
            'RateLimiter', 'Limiter', 'rate_limited'
        }
        
        # Verificar decorators
        for decorator in func_node.decorator_list:
            decorator_name = self._get_full_name(decorator)
            if any(indicator in decorator_name.lower() for indicator in rate_limit_indicators):
                return True
        
        # Verificar chamadas dentro da função
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call):
                func_name = self._get_full_name(node.func)
                if any(indicator in func_name.lower() for indicator in rate_limit_indicators):
                    return True
        
        return False
    
    def _check_session_expiration(self, func_node: ast.FunctionDef) -> bool:
        """Verifica se sessão/token tem expiração"""
        expiration_keywords = {
            'expire', 'expiration', 'expiry', 'exp',
            'ttl', 'timeout', 'max_age', 'maxage',
            'lifetime', 'duration', 'valid_for'
        }
        
        for node in ast.walk(func_node):
            # Verificar argumentos de função
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    if any(exp in keyword.arg.lower() for exp in expiration_keywords):
                        return True
            
            # Verificar atribuições
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id.lower()
                        if any(exp in var_name for exp in expiration_keywords):
                            return True
        
        return False
    
    def _check_information_disclosure(self, func_node: ast.FunctionDef):
        """Detecta revelação de informação em erros de autenticação"""
        # Procurar returns ou raises com mensagens diferentes para usuário/senha
        for node in ast.walk(func_node):
            if isinstance(node, ast.Return) and node.value:
                # Verificar se retorna mensagens específicas
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    msg = node.value.value.lower()
                    
                    # Mensagens que revelam informação
                    revealing_patterns = [
                        'user not found', 'username not found', 'invalid username',
                        'wrong password', 'incorrect password', 'invalid password',
                        'user does not exist', 'username does not exist',
                        'password mismatch', 'incorrect credentials'
                    ]
                    
                    if any(pattern in msg for pattern in revealing_patterns):
                        self.problems.append(Vulnerability(
                            line=node.lineno,
                            column=node.col_offset,
                            type='Authentication Information Disclosure',
                            function=func_node.name,
                            pattern='specific error message',
                            description=f"Authentication error reveals whether username or password is incorrect. Use generic messages like 'Invalid credentials'.",
                            severity="LOW",
                            confidence="HIGH",
                            category="A07"
                        ))
    
    def visit_Call(self, node: ast.Call):
        """Detecta chamadas inseguras e credenciais em argumentos"""
        func_name = self._get_full_name(node.func)
        
        # --- MELHORIA 1: Detetar credenciais passadas como argumentos ---
        # Ex: db.connect(password="secret")
        for keyword in node.keywords:
            # Se o nome do argumento for suspeito (ex: 'password', 'api_key')
            if keyword.arg and self._is_credential_variable(keyword.arg):
                # E o valor for uma string fixa
                if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                    string_value = keyword.value.value
                    
                    # Usa a tua lógica existente de filtragem
                    if string_value.lower() in {'', 'none', 'null', 'todo', 'changeme'}:
                        continue
                        
                    # Verifica se parece um segredo real
                    pattern_match = self._is_suspicious_string(string_value)
                    
                    if pattern_match or (len(string_value) > 0): # Se é argumento nomeado 'password', qualquer string é suspeita
                         self.problems.append(Vulnerability(
                            line=node.lineno,
                            column=node.col_offset,
                            type='Hardcoded Credential in Call',
                            function=self.current_function or 'module level',
                            pattern=f"argument '{keyword.arg}' with hardcoded value",
                            description=f"Passing hardcoded credentials ('{keyword.arg}') to function '{func_name}'. Use environment variables.",
                            severity="HIGH",
                            confidence="HIGH",
                            category="A07"
                        ))
                        # Adiciona aos encontrados para evitar duplicados se necessário
                         self.found_credentials.add(keyword.arg)

        # --- FIM DA MELHORIA 1 ---

        # Detectar uso de algoritmos fracos para hashing de passwords
        weak_hash_functions = {'md5', 'sha1', 'sha256'}  # SHA256 sozinho é fraco para passwords
        
        if any(weak in func_name.lower() for weak in weak_hash_functions):
            # Verificar se está sendo usado para passwords
            if self.current_function and any(pwd in self.current_function.lower() for pwd in {'password', 'passwd', 'pwd', 'hash'}):
                self.problems.append(Vulnerability(
                    line=node.lineno,
                    column=node.col_offset,
                    type='Weak Password Hashing',
                    function=self.current_function,
                    pattern=f"using {func_name}",
                    description=f"Using '{func_name}' for password hashing is insecure. Use bcrypt, scrypt, or Argon2 instead.",
                    severity="HIGH",
                    confidence="MEDIUM",
                    category="A07"
                ))
        
        # Detectar JWT sem verificação de assinatura
        if 'jwt.decode' in func_name.lower():
            # Verificar se tem verify=False ou não verifica assinatura
            has_verification = True
            for keyword in node.keywords:
                if keyword.arg in {'verify', 'verify_signature', 'options'}:
                    if isinstance(keyword.value, ast.Constant):
                        if keyword.value.value is False:
                            has_verification = False
                    elif isinstance(keyword.value, ast.Dict):
                        # Verificar options dict
                        for i, key in enumerate(keyword.value.keys):
                            if isinstance(key, ast.Constant) and key.value == 'verify_signature':
                                val = keyword.value.values[i]
                                if isinstance(val, ast.Constant) and val.value is False:
                                    has_verification = False
            
            # --- MELHORIA 2: Detetar algoritmo 'none' no JWT ---
            # Ex: jwt.decode(..., algorithms=['none'])
                if keyword.arg == 'algorithms':
                     if isinstance(keyword.value, (ast.List, ast.Tuple)):
                         for elt in keyword.value.elts:
                             if isinstance(elt, ast.Constant) and elt.value == 'none':
                                 self.problems.append(Vulnerability(
                                    line=node.lineno,
                                    column=node.col_offset,
                                    type='Insecure JWT Algorithm',
                                    function=self.current_function or 'unknown',
                                    pattern="algorithms=['none']",
                                    description="Allowing 'none' algorithm in JWT leads to signature bypass.",
                                    severity="HIGH",
                                    confidence="HIGH",
                                    category="A07"
                                ))
          

            if not has_verification:
                self.problems.append(Vulnerability(
                    line=node.lineno,
                    column=node.col_offset,
                    type='JWT Signature Not Verified',
                    function=self.current_function or 'unknown',
                    pattern='jwt.decode with verify=False',
                    description="JWT token decoded without signature verification. This allows token tampering.",
                    severity="HIGH",
                    confidence="HIGH",
                    category="A07"
                ))
        
        self.generic_visit(node)