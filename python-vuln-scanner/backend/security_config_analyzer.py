"""
A02:2025 - Security Misconfiguration Analyzer
Deteta configurações de segurança inadequadas em aplicações Python
"""

import ast
from typing import List
from models import Vulnerability

class SecurityConfigAnalyzer(ast.NodeVisitor):
    """
    Analisa configurações inseguras relacionadas com:
    - Debug mode ativado em produção
    - Configurações de CORS permissivas
    - Secret keys hardcoded
    - Configurações de servidor inseguras (host, port)
    - Cabeçalhos de segurança ausentes
    """
    
    def __init__(self):
        self.problems: List[Vulnerability] = []
        self.current_line = 0
        
        # Padrões perigosos de configuração
        self.debug_patterns = {'DEBUG', 'debug', 'FLASK_DEBUG', 'DJANGO_DEBUG'}
        self.insecure_hosts = {'0.0.0.0', '::'}
        self.cors_all_origins = {'*', 'http://*', 'https://*'}
        
    def visit_Assign(self, node: ast.Assign) -> None:
        """Deteta atribuições de configuração inseguras"""
        self.current_line = node.lineno
        
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                
                # 1. Debug mode ativado
                if var_name in self.debug_patterns:
                    if self._is_true_value(node.value):
                        self.problems.append(Vulnerability(
                            line=node.lineno,
                            column=node.col_offset,
                            type="Debug Mode Enabled",
                            function=var_name,
                            pattern="debug=True",
                            description=f"Debug mode is enabled via {var_name}=True. "
                                       f"This exposes sensitive information in error messages.",
                            severity="HIGH",
                            confidence="HIGH",
                            category="A02"
                        ))
                
                # 2. Secret key hardcoded
                if 'SECRET' in var_name.upper() or 'KEY' in var_name.upper():
                    if isinstance(node.value, ast.Constant):
                        self.problems.append(Vulnerability(
                            line=node.lineno,
                            column=node.col_offset,
                            type="Hardcoded Secret Key",
                            function=var_name,
                            pattern="SECRET_KEY = 'literal'",
                            description=f"Secret key '{var_name}' is hardcoded. "
                                       f"Use environment variables instead.",
                            severity="HIGH",
                            confidence="HIGH",
                            category="A02"
                        ))
                
                # 3. Configuração de CORS permissiva
                if 'CORS' in var_name.upper() and 'ORIGIN' in var_name.upper():
                    if self._is_permissive_cors(node.value):
                        self.problems.append(Vulnerability(
                            line=node.lineno,
                            column=node.col_offset,
                            type="Permissive CORS Configuration",
                            function=var_name,
                            pattern="CORS_ORIGINS = '*'",
                            description="CORS is configured to allow all origins (*). "
                                       "Specify explicit origins instead.",
                            severity="MEDIUM",
                            confidence="HIGH",
                            category="A02"
                        ))
        
        self.generic_visit(node)
    
    def visit_Call(self, node: ast.Call) -> None:
        """Deteta chamadas de função com configurações inseguras"""
        self.current_line = node.lineno
        func_name = self._get_func_name(node.func)
        
        # Flask app.run() com debug=True
        if 'run' in func_name or 'listen' in func_name:
            for keyword in node.keywords:
                # Debug mode
                if keyword.arg == 'debug':
                    if self._is_true_value(keyword.value):
                        self.problems.append(Vulnerability(
                            line=node.lineno,
                            column=node.col_offset,
                            type="Debug Mode in Production",
                            function=func_name,
                            pattern="app.run(debug=True)",
                            description="Application is running with debug=True. "
                                       "Disable debug mode in production.",
                            severity="HIGH",
                            confidence="HIGH",
                            category="A02"
                        ))
                
                # Host inseguro (0.0.0.0)
                if keyword.arg == 'host':
                    if isinstance(keyword.value, ast.Constant):
                        host_value = keyword.value.value
                        if host_value in self.insecure_hosts:
                            self.problems.append(Vulnerability(
                                line=node.lineno,
                                column=node.col_offset,
                                type="Insecure Host Binding",
                                function=func_name,
                                pattern=f"app.run(host='{host_value}')",
                                description=f"Application is binding to {host_value}, "
                                           f"which exposes it to all network interfaces.",
                                severity="MEDIUM",
                                confidence="HIGH",
                                category="A02"
                            ))
                
                # SSL desativado
                if keyword.arg == 'ssl' or keyword.arg == 'ssl_context':
                    if isinstance(keyword.value, ast.Constant) and keyword.value.value is None:
                        self.problems.append(Vulnerability(
                            line=node.lineno,
                            column=node.col_offset,
                            type="SSL Disabled",
                            function=func_name,
                            pattern="ssl_context=None",
                            description="SSL/TLS is explicitly disabled. "
                                       "Enable HTTPS for production.",
                            severity="HIGH",
                            confidence="HIGH",
                            category="A02"
                        ))
        
        # Configurações de CORS permissivas (Flask-CORS)
        if 'CORS' in func_name:
            for keyword in node.keywords:
                if keyword.arg == 'origins' or keyword.arg == 'allow_origins':
                    if self._is_permissive_cors(keyword.value):
                        self.problems.append(Vulnerability(
                            line=node.lineno,
                            column=node.col_offset,
                            type="Permissive CORS",
                            function=func_name,
                            pattern="CORS(origins='*')",
                            description="CORS allows all origins. Specify explicit domains.",
                            severity="MEDIUM",
                            confidence="HIGH",
                            category="A02"
                        ))
        
        # Verificação de SSL desativada (requests, urllib)
        if 'get' in func_name or 'post' in func_name or 'request' in func_name:
            for keyword in node.keywords:
                if keyword.arg == 'verify':
                    if self._is_false_value(keyword.value):
                        self.problems.append(Vulnerability(
                            line=node.lineno,
                            column=node.col_offset,
                            type="SSL Verification Disabled",
                            function=func_name,
                            pattern="requests.get(url, verify=False)",
                            description="SSL certificate verification is disabled. "
                                       "This allows man-in-the-middle attacks.",
                            severity="HIGH",
                            confidence="HIGH",
                            category="A02"
                        ))
        
        self.generic_visit(node)
    
    def _get_func_name(self, func_node: ast.AST) -> str:
        """Extrai o nome completo de uma função"""
        if isinstance(func_node, ast.Name):
            return func_node.id
        elif isinstance(func_node, ast.Attribute):
            return f"{self._get_func_name(func_node.value)}.{func_node.attr}"
        return ""
    
    def _is_true_value(self, node: ast.AST) -> bool:
        """Verifica se um nó representa True"""
        if isinstance(node, ast.Constant):
            return node.value is True
        elif isinstance(node, ast.NameConstant):
            return node.value is True
        return False
    
    def _is_false_value(self, node: ast.AST) -> bool:
        """Verifica se um nó representa False"""
        if isinstance(node, ast.Constant):
            return node.value is False
        elif isinstance(node, ast.NameConstant):
            return node.value is False
        return False
    
    def _is_permissive_cors(self, node: ast.AST) -> bool:
        """Verifica se a configuração de CORS é permissiva"""
        if isinstance(node, ast.Constant):
            value = node.value
            if isinstance(value, str) and value in self.cors_all_origins:
                return True
        elif isinstance(node, ast.List):
            for elt in node.elts:
                if isinstance(elt, ast.Constant):
                    if elt.value in self.cors_all_origins:
                        return True
        return False
