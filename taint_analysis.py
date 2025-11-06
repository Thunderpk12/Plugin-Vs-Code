"""
Eng:A03:2021 - Taint Analysis (Taint Analysis)

This module implements taint analysis to track the flow of 
untrusted (tainted) data through the application.
-----------------------------------------------------------
Pt:A03:2021 - Análise de Taint (Taint Analysis)

Este módulo implementa a análise de taint para rastrear o fluxo de dados 
não confiáveis (tainted) através da aplicação.
"""

import ast
from typing import Set

class TaintAnalyzer(ast.NodeVisitor):
    """
    Eng: Implements taint analysis to track untrusted data flow.
    Pt: Implementa análise de taint para rastrear fluxo de dados não confiáveis.
    """
    
    # Sources: Origens de dados não confiáveis
    SOURCES = {
        'request.args', 'request.form', 'request.json', 'request.data',
        'request.args.get', 'request.form.get', 'request.json.get',
        'request.GET', 'request.POST', 'request.FILES', 'request.cookies',
        'input', 'raw_input', 'sys.argv', 'os.environ', 'os.environ.get',
        'socket.recv', 'urlopen', 'requests.get', 'requests.post',
    }
    
    # Sanitizers: Funções que limpam dados
    SANITIZERS = {
        'int', 'float', 'bool', 'str.isdigit', 'str.isalpha', 'str.isalnum',
        'html.escape', 'urllib.parse.quote', 'shlex.quote',
        'django.utils.html.escape', 'markupsafe.escape',
        'escape_filter_chars', 'escape_dn_chars',
        'validate', 'sanitize', 'clean', 'filter', 'whitelist',
        're.match', 're.search', 're.fullmatch',
        'ast.literal_eval',
        'SandboxedEnvironment',
        'json.dumps',
    }
    
    def __init__(self):
        self.tainted_vars: Set[str] = set()
        self.clean_vars: Set[str] = set()
        self.tainted_lines: Set[int] = set()
        
    def _get_full_name(self, node: ast.AST) -> str:
        """
        Eng:Gets the full qualified name
        Pt:Obtém o nome qualificado completo 
        """
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            parent = self._get_full_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        elif isinstance(node, ast.Call):
            return self._get_full_name(node.func)
        return ""
    
    def _is_source(self, node: ast.AST) -> bool:
        """
        Eng:Checks if the node is a source (untrusted origin)
        Pt:Verifica se o nó é uma source (origem não confiável)
        """
        if isinstance(node, ast.Call):
            func_name = self._get_full_name(node.func)
            return any(source in func_name for source in self.SOURCES)
        
        if isinstance(node, ast.Attribute):
            full_name = self._get_full_name(node)
            return any(source in full_name for source in self.SOURCES)
        
        return False
    
    def _is_sanitizer(self, node: ast.AST) -> bool:
        """
        Eng:Checks if the node is a sanitizer
        Pt:Verifica se o nó é um sanitizer
        """
        if not isinstance(node, ast.Call):
            return False

        func_name = self._get_full_name(node.func)
        
        if any(san in func_name for san in self.SANITIZERS):
            return True
        
        # Heurística para str.replace('\n', '')
        if func_name.endswith('.replace'):
            if len(node.args) >= 2 and isinstance(node.args[0], ast.Constant) and isinstance(node.args[1], ast.Constant):
                return True

        # Heurística para XMLParser(resolve_entities=False)
        if 'XMLParser' in func_name:
            for kw in node.keywords:
                if kw.arg == 'resolve_entities' and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    return True
        
        safe_words = ['validate', 'sanitize', 'clean', 'escape', 'quote', 'filter']
        if any(word in func_name.lower() for word in safe_words):
            return True
        
        return False
    
    def _is_tainted(self, node: ast.AST) -> bool:
        """
        Eng:Checks if a node contains tainted data
        Pt:Verifica se um nó contém dados tainted
        """
        if isinstance(node, ast.Constant):
            return False
        
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars and node.id not in self.clean_vars
        
        if self._is_source(node):
            return True
        
        if isinstance(node, ast.Attribute):
            if self._is_source(node):
                return True
            return self._is_tainted(node.value)
        
        if isinstance(node, ast.Subscript):
            return self._is_tainted(node.value)
        
        if isinstance(node, ast.BinOp):
            return self._is_tainted(node.left) or self._is_tainted(node.right)
        
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    if self._is_tainted(value.value):
                        return True
        
        if isinstance(node, ast.Call):
            if self._is_sanitizer(node):
                return False # Chamada a sanitizer é considerada limpa
            
            # Propagação conservadora: se algum arg é tainted, o resultado é tainted
            for arg in node.args:
                if self._is_tainted(arg):
                    return True
            for kw in node.keywords:
                if self._is_tainted(kw.value):
                    return True
        
        return False
    
    def visit_Assign(self, node: ast.Assign):
        """
        Eng:Tracks assignments to propagate taint
        Pt:Rastreia atribuições para propagar taint
        """
        is_tainted = self._is_tainted(node.value)
        is_sanitized = self._is_sanitizer(node.value)
        
        if is_tainted:
            self.tainted_lines.add(node.lineno)
        
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                
                if is_tainted and not is_sanitized:
                    self.tainted_vars.add(var_name)
                    self.clean_vars.discard(var_name)
                elif is_sanitized:
                    self.clean_vars.add(var_name)
                    self.tainted_vars.discard(var_name)
        
        self.generic_visit(node)
    
    def visit_Call(self, node: ast.Call):
        """
        Eng:Marks lines where tainted data is used and cleans vars in sanitizers
        Pt:Marca linhas onde dados tainted são usados e limpa vars em sanitizers
        """
        
        # Limpar variáveis se for um sanitizer
        if self._is_sanitizer(node):
            for arg in node.args:
                if isinstance(arg, ast.Name):
                    self.clean_vars.add(arg.id)
                    self.tainted_vars.discard(arg.id)

        # Marcar linha como tainted se um arg for tainted
        for arg in node.args:
            if self._is_tainted(arg):
                self.tainted_lines.add(node.lineno)
                break
        
        for kw in node.keywords:
            if self._is_tainted(kw.value):
                self.tainted_lines.add(node.lineno)
                break
                
        self.generic_visit(node)
    
    def is_line_tainted(self, line: int) -> bool:
        """
        Eng:Checks if a specific line is tainted
        Pt:Verifica se uma linha específica tem dados tainted
        """
        return line in self.tainted_lines