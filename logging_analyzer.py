"""
A09:2021 - Falhas de Logging e Monitorização de Segurança
"""

import ast
from typing import List
from models import Vulnerability

class LoggingMonitorAnalyzer(ast.NodeVisitor):
    """
    Detecta falhas de logging de segurança em operações críticas
    e em tratamento de exceções.
    """
        
    # Operações que DEVEM ter logging de auditoria
    CRITICAL_OPERATIONS = {
        'login', 'logout', 'authenticate', 'authorize',
        'delete', 'remove', 'drop', 'admin', 'sudo',
        'create_user', 'update_password', 'grant_permission',
        'reset_password', 'change_role'
    }
        
    # Funções que contam como logging
    LOGGING_FUNCTIONS = {
        'logging.info', 'logging.warning', 'logging.error', 
        'logging.critical', 'logger.info', 'logger.warning',
        'logger.error', 'logger.critical', 'log.info', 'log.warning',
        'log.error', 'log.critical', 'audit', 'security_log'
    }
        
    def __init__(self):
        self.problems: List[Vulnerability] = []
        self.current_function = None
        
    def _get_full_name(self, node: ast.AST) -> str:
        """Helper para obter nomes como 'logging.info'"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            parent = self._get_full_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""

    def _function_contains_logging(self, func_node: ast.FunctionDef) -> bool:
        """Verifica se um nó de função contém chamadas de logging"""
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call):
                func_name = self._get_full_name(node.func)
                if any(log in func_name for log in self.LOGGING_FUNCTIONS):
                    return True
        return False

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Verifica funções críticas por falta de logging"""
        self.current_function = node.name
        has_logging = self._function_contains_logging(node)
        
        # Verifica se o nome da função corresponde a uma operação crítica
        is_critical = any(op in node.name.lower() for op in self.CRITICAL_OPERATIONS)
                
        if is_critical and not has_logging:
            self.problems.append(Vulnerability(
                line=node.lineno,
                column=node.col_offset,
                type='Security Logging Failure',
                function=node.name,
                pattern='missing audit log',
                description=f"Critical operation '{node.name}' appears to have no security logging.",
                severity="MEDIUM",
                confidence="HIGH",
                category="A09"  # Categoria de Logging
            ))
                
        self.generic_visit(node)
        self.current_function = None
        
    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        """Verifica 'except' blocks por falta de logging"""
        has_logging = False
                
        for child in node.body:
            # Procurar por chamadas de logging
            for sub_node in ast.walk(child):
                if isinstance(sub_node, ast.Call):
                    func_name = self._get_full_name(sub_node.func)
                    if any(log in func_name for log in self.LOGGING_FUNCTIONS):
                        has_logging = True
                        break
            if has_logging:
                break
        
        # Ignorar 'pass' simples
        is_pass = len(node.body) == 1 and isinstance(node.body[0], ast.Pass)
        # Ignorar 'raise' (está a propagar a exceção)
        is_raise = any(isinstance(child, ast.Raise) for child in node.body)

        if not has_logging and not is_pass and not is_raise:
            self.problems.append(Vulnerability(
                line=node.lineno,
                column=node.col_offset,
                type='Unlogged Exception',
                function=self.current_function or 'unknown (global scope)',
                pattern='exception caught without logging',
                description="Exception caught without logging. This can hide errors or security issues.",
                severity="LOW",
                confidence="MEDIUM",
                category="A09" # Categoria de Logging
            ))
                
        self.generic_visit(node)