"""
Pt: A01:2021 - Broken Access Control
Eng: A01:2021 - Broken Access Control

Este analisador deteta:
- Rotas web (Flask/Django) sem proteção de login/permissão
- Configurações permissivas de CORS
- Padrões de Directory Traversal
"""

import ast
from typing import List, Set, Optional
from models import Vulnerability

class AccessControlAnalyzer(ast.NodeVisitor):
    """
    Pt: Analisa falhas de controlo de acesso
    """
    
    # Decoradores que definem rotas web
    ROUTE_DECORATORS = {
        'app.route', 'bp.route', 'blueprint.route',  # Flask
        'path', 're_path', 'url'                     # Django urls
    }
    
    # Decoradores que indicam proteção
    SECURITY_DECORATORS = {
        'login_required', 'login_required()',
        'permission_required', 'admin_required',
        'staff_member_required', 'user_passes_test',
        'superuser_required', 'jwt_required',
        'auth_required', 'requires_auth'
    }
    
    # Rotas que geralmente são públicas (Whitelist)
    PUBLIC_ROUTES = {
        'login', 'signin', 'register', 'signup', 
        'index', 'home', 'about', 'contact', 
        'health', 'status', 'public'
    }

    def __init__(self):
        self.problems: List[Vulnerability] = []

    def _get_decorator_name(self, node: ast.AST) -> str:
        """Helper para obter o nome do decorador"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_decorator_name(node.value)}.{node.attr}"
        elif isinstance(node, ast.Call):
            return self._get_decorator_name(node.func)
        return ""

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """
        Verifica se funções de rota têm proteção
        """
        decorators = [self._get_decorator_name(d) for d in node.decorator_list]
        
        # 1. Verificar se é uma Rota Web
        is_route = False
        for dec in decorators:
            if any(r in dec for r in self.ROUTE_DECORATORS):
                is_route = True
                break
        
        if is_route:
            # Ignorar rotas públicas (Login, Home, etc.)
            if any(public in node.name.lower() for public in self.PUBLIC_ROUTES):
                self.generic_visit(node)
                return

            # 2. Verificar se tem proteção
            has_protection = False
            for dec in decorators:
                if any(sec in dec for sec in self.SECURITY_DECORATORS):
                    has_protection = True
                    break
            
            if not has_protection:
                self.problems.append(Vulnerability(
                    line=node.lineno,
                    column=node.col_offset,
                    type='Missing Access Control',
                    function=node.name,
                    pattern='route without @login_required',
                    description=f"Web route '{node.name}' seems unprotected. Consider adding '@login_required' or similar.",
                    severity="HIGH",
                    confidence="MEDIUM",
                    category="A01"
                ))

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        """
        Deteta configurações inseguras (CORS)
        """
        # Verificar CORS (Cross-Origin Resource Sharing)
        for target in node.targets:
            if isinstance(target, ast.Name):
                if 'CORS_ORIGIN_ALLOW_ALL' in target.id:
                    if isinstance(node.value, ast.Constant) and node.value.value is True:
                        self.problems.append(Vulnerability(
                            line=node.lineno,
                            column=node.col_offset,
                            type='Insecure CORS Configuration',
                            function='configuration',
                            pattern='CORS_ORIGIN_ALLOW_ALL = True',
                            description="Allowing all origins (CORS) enables data theft from malicious sites.",
                            severity="HIGH",
                            confidence="HIGH",
                            category="A01"
                        ))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """
        Deteta Directory Traversal básico
        """
        if isinstance(node.func, ast.Name) and node.func.id == 'open':
            if node.args:
                arg = node.args[0]
                # Se estiver a concatenar algo com ".." ou não validar input
                if isinstance(arg, ast.BinOp):
                     self.problems.append(Vulnerability(
                        line=node.lineno,
                        column=node.col_offset,
                        type='Potential Directory Traversal',
                        function='open',
                        pattern='open(... + ...)',
                        description="File open with dynamic path. Ensure input is sanitized against '../' traversal.",
                        severity="MEDIUM",
                        confidence="LOW",
                        category="A01"
                    ))
        self.generic_visit(node)