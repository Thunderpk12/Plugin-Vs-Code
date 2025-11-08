"""
Enhanced A09 Logging and Monitoring Analyzer
"""

import ast
from typing import List, Set, Dict, Optional
from models import Vulnerability

class LoggingAnalyzer(ast.NodeVisitor):
    """
    Eng: Logging analysis with:
    - Sensitive data detection in logs
    - Appropriate log level checking
    - Critical operation without audit detection
    - Exception context analysis      
    
    
    Pt: Análise de logging com:
    - Detecção de dados sensíveis em logs
    - Verificação de níveis de log apropriados
    - Detecção de operações críticas sem auditoria
    - Análise de contexto de exceções
    """
    
    # Operações que devem ter logging
    CRITICAL_OPERATIONS = {
        'login', 'logout', 'authenticate', 'authorize', 'auth',
        'delete', 'remove', 'drop', 'truncate',
        'admin', 'sudo', 'elevate',
        'create_user', 'update_password', 'grant_permission', 'revoke',
        'reset_password', 'change_role', 'change_email',
        'payment', 'transaction', 'transfer', 'charge',
        'export', 'backup', 'restore',
    }
    
    # Operações de escrita/modificação
    WRITE_OPERATIONS = {
        'insert', 'update', 'delete', 'modify', 'save', 'write',
        'create', 'add', 'remove', 'put', 'post', 'patch',
    }
    
    # Funções de logging
    LOGGING_FUNCTIONS = {
        'logging.debug', 'logging.info', 'logging.warning', 'logging.error',
        'logging.critical', 'logging.exception',
        'logger.debug', 'logger.info', 'logger.warning', 'logger.error',
        'logger.critical', 'logger.exception',
        'log.debug', 'log.info', 'log.warning', 'log.error', 'log.critical',
        'audit', 'audit_log', 'security_log',
    }
    
    # Palavras que indicam dados sensíveis
    SENSITIVE_KEYWORDS = {
        'password', 'passwd', 'pwd', 'secret', 'token', 'key', 'api_key',
        'credit_card', 'card_number', 'cvv', 'ssn', 'social_security',
        'pin', 'private_key', 'certificate', 'auth_token', 'session_id',
        'bearer', 'oauth', 'credential',
    }
    
    # Níveis mínimos recomendados por tipo de operação
    MIN_LOG_LEVELS = {
        'security_event': 'warning',  # login, logout, auth failures
        'data_modification': 'info',   # updates, deletes
        'error': 'error',              # exceptions
        'critical_operation': 'warning',  # admin actions, payments
    }
    
    def __init__(self):
        self.problems: List[Vulnerability] = []
        self.current_function: Optional[str] = None
        self.current_function_node: Optional[ast.FunctionDef] = None
        
    def _get_full_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            parent = self._get_full_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""
    
    def _extract_log_message(self, call_node: ast.Call) -> str:
        """
        Eng: Extracts the log message from a call
        Pt:Extrai a mensagem de log de uma chamada
        """
        if call_node.args:
            arg = call_node.args[0]
            if isinstance(arg, ast.Constant):
                return str(arg.value)
            elif isinstance(arg, ast.JoinedStr):
                # f-string
                parts = []
                for value in arg.values:
                    if isinstance(value, ast.Constant):
                        parts.append(str(value.value))
                    elif isinstance(value, ast.FormattedValue):
                        if isinstance(value.value, ast.Name):
                            parts.append(f"{{{value.value.id}}}")
                        else:
                            parts.append("{...}")
                return "".join(parts)
        return ""
    
    def _contains_sensitive_data(self, node: ast.AST) -> Optional[str]:
        """
        Eng: Checks if a node contains sensitive data
        Pt:Verifica se um nó contém dados sensíveis
        """
        if isinstance(node, ast.Name):
            var_name = node.id.lower()
            for keyword in self.SENSITIVE_KEYWORDS:
                if keyword in var_name:
                    return keyword
        
        if isinstance(node, ast.Constant):
            value_str = str(node.value).lower()
            for keyword in self.SENSITIVE_KEYWORDS:
                if keyword in value_str:
                    return keyword
        
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    sensitive = self._contains_sensitive_data(value.value)
                    if sensitive:
                        return sensitive
        
        if isinstance(node, ast.BinOp):
            left_sensitive = self._contains_sensitive_data(node.left)
            if left_sensitive:
                return left_sensitive
            right_sensitive = self._contains_sensitive_data(node.right)
            if right_sensitive:
                return right_sensitive
        
        return None
    
    def _get_log_level(self, func_name: str) -> Optional[str]:
        """
        Eng: Extracts the log level from the function
        pT:Extrai o nível de log da função
        """
        func_lower = func_name.lower()
        if 'debug' in func_lower:
            return 'debug'
        elif 'info' in func_lower:
            return 'info'
        elif 'warning' in func_lower or 'warn' in func_lower:
            return 'warning'
        elif 'error' in func_lower:
            return 'error'
        elif 'critical' in func_lower:
            return 'critical'
        return None
    
    def _is_security_critical(self, func_name: str) -> bool:
        """
        Eng: Checks if the function is security critical
        Pt:Verifica se a função é crítica de segurança
        """
        func_lower = func_name.lower()
        return any(op in func_lower for op in self.CRITICAL_OPERATIONS)
    
    def _is_data_modification(self, func_name: str) -> bool:
        """
        Eng: Verifica se a função modifica dados
        Pt: Checks if the function modifies data
        """
        func_lower = func_name.lower()
        return any(op in func_lower for op in self.WRITE_OPERATIONS)
    
    def _function_contains_logging(self, func_node: ast.FunctionDef) -> bool:
        """
        Eng: Checks if a function contains logging
        Pt:Verifica se uma função contém logging
        """
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call):
                func_name = self._get_full_name(node.func)
                if any(log in func_name for log in self.LOGGING_FUNCTIONS):
                    return True
        return False
    
    def _get_operation_type(self, func_name: str) -> Optional[str]:
        """
        Eng: Determines the type of operation
        Pt:Determina o tipo de operação
        """
        if self._is_security_critical(func_name):
            return 'critical_operation'
        elif self._is_data_modification(func_name):
            return 'data_modification'
        return None
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Analisa funções por falta de logging apropriado"""
        self.current_function = node.name
        self.current_function_node = node
        
        has_logging = self._function_contains_logging(node)
        operation_type = self._get_operation_type(node.name)
        
        # Verificar se operação crítica tem logging
        if operation_type and not has_logging:
            severity = "HIGH" if operation_type == 'critical_operation' else "MEDIUM"
            
            self.problems.append(Vulnerability(
                line=node.lineno,
                column=node.col_offset,
                type='Missing Security Logging',
                function=node.name,
                pattern='no audit trail',
                description=f"Function '{node.name}' performs {operation_type} but has no security logging.",
                severity=severity,
                confidence="HIGH",
                category="A09"
            ))
        
        # Analisar logs dentro da função
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                self._analyze_log_call(child)
        
        self.generic_visit(node)
        self.current_function = None
        self.current_function_node = None
    
    def _analyze_log_call(self, node: ast.Call):
        """Analisa uma chamada de logging específica"""
        func_name = self._get_full_name(node.func)
        
        # Verificar se é função de logging
        if not any(log in func_name for log in self.LOGGING_FUNCTIONS):
            return
        
        log_level = self._get_log_level(func_name)
        
        # Verificar dados sensíveis nos argumentos
        for arg in node.args:
            sensitive = self._contains_sensitive_data(arg)
            if sensitive:
                self.problems.append(Vulnerability(
                    line=node.lineno,
                    column=node.col_offset,
                    type='Sensitive Data in Logs',
                    function=self.current_function or 'unknown',
                    pattern=f"sensitive data: {sensitive}",
                    description=f"Logging contains sensitive data ('{sensitive}'). This may expose confidential information.",
                    severity="HIGH",
                    confidence="HIGH",
                    category="A09"
                ))
        
        # Verificar nível de log apropriado para operação crítica
        if self.current_function_node:
            operation_type = self._get_operation_type(self.current_function_node.name)
            if operation_type and log_level:
                min_level = self.MIN_LOG_LEVELS.get(operation_type)
                if min_level:
                    levels_order = ['debug', 'info', 'warning', 'error', 'critical']
                    if levels_order.index(log_level) < levels_order.index(min_level):
                        self.problems.append(Vulnerability(
                            line=node.lineno,
                            column=node.col_offset,
                            type='Inappropriate Log Level',
                            function=self.current_function or 'unknown',
                            pattern=f"using {log_level} for {operation_type}",
                            description=f"Security event logged at '{log_level}' level, should be at least '{min_level}'.",
                            severity="LOW",
                            confidence="MEDIUM",
                            category="A09"
                        ))
    
    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        """Analisa tratamento de exceções"""
        has_logging = False
        has_sensitive_in_log = False
        
        # Procurar logging
        for child in node.body:
            for sub_node in ast.walk(child):
                if isinstance(sub_node, ast.Call):
                    func_name = self._get_full_name(sub_node.func)
                    if any(log in func_name for log in self.LOGGING_FUNCTIONS):
                        has_logging = True
                        
                        # Verificar se loga a exceção completa (pode conter dados sensíveis)
                        for arg in sub_node.args:
                            if isinstance(arg, ast.Name) and node.name and arg.id == node.name.id:
                                # Logando o objeto de exceção diretamente
                                self.problems.append(Vulnerability(
                                    line=sub_node.lineno,
                                    column=sub_node.col_offset,
                                    type='Exception Object Logged',
                                    function=self.current_function or 'unknown',
                                    pattern='logging exception object',
                                    description="Full exception object logged. This may expose sensitive data from stack traces.",
                                    severity="MEDIUM",
                                    confidence="MEDIUM",
                                    category="A09"
                                ))
                        break
            if has_logging:
                break
        
       
        is_pass = len(node.body) == 1 and isinstance(node.body[0], ast.Pass)
        is_raise = any(isinstance(child, ast.Raise) for child in node.body)
        
        if not has_logging and not is_pass and not is_raise:
           
            severity = "MEDIUM"
            if self.current_function_node:
                if self._is_security_critical(self.current_function_node.name):
                    severity = "HIGH"
            
            self.problems.append(Vulnerability(
                line=node.lineno,
                column=node.col_offset,
                type='Unlogged Exception',
                function=self.current_function or 'unknown',
                pattern='silent exception handling',
                description="Exception caught without logging. Security events or errors may be hidden.",
                severity=severity,
                confidence="MEDIUM",
                category="A09"
            ))
        
        self.generic_visit(node)