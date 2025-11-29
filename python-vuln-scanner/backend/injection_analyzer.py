"""
Pt:A03:2021 - Analisadores de Injeção
Eng:A03:2021 - Injection Analyzers
"""

import ast
from typing import List, Optional
from models import Vulnerability

# ===================== BASE ANALYZER =====================

class BaseInjectionAnalyzer(ast.NodeVisitor):
    """
    Eng:Base class for detecting injection patterns
    Pt:Classe base para detecção de padrões de injeção
    """
    risky_function_names: set = set()
    vulnerability_type: str = "GENERIC_INJECTION"

    def __init__(self):
        self.problems: List[Vulnerability] = []

    def _get_function_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        if isinstance(node.func, ast.Name):
            return node.func.id
        return ""
    
    def _get_full_obj_name(self, node: ast.AST) -> str:
        """
        Eng: Helper to get the object name (e.g., 'db' in 'db.users.find')    
        Pt:  Helper para obter o nome do objeto (ex: 'db' em 'db.users.find')
        """
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return self._get_full_obj_name(node.value)
        if isinstance(node, ast.Call):
            return self._get_full_obj_name(node.func)
        return ""

    def _is_literal_safe(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Constant):
            return True
        
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return all(self._is_literal_safe(elt) for elt in node.elts)
        
        if isinstance(node, ast.Dict):
            keys_safe = all(self._is_literal_safe(k) for k in node.keys if k is not None)
            values_safe = all(self._is_literal_safe(v) for v in node.values)
            return keys_safe and values_safe
        
        return False

    def _check_argument_for_injection(self, arg_node: ast.AST) -> Optional[str]:
        if self._is_literal_safe(arg_node):
            return None

        if isinstance(arg_node, ast.JoinedStr):
            if any(isinstance(val, ast.FormattedValue) for val in arg_node.values):
                return "f-string with variables"
            return None 

        if isinstance(arg_node, ast.BinOp):
            left_check = self._check_argument_for_injection(arg_node.left)
            right_check = self._check_argument_for_injection(arg_node.right)
            
            if left_check or right_check:
                return left_check or right_check
            
            if self._is_literal_safe(arg_node.left) and self._is_literal_safe(arg_node.right):
                return None
                    
            if isinstance(arg_node.op, (ast.Add, ast.Mod)):
                return "string concatenation/formatting with variables"

        if isinstance(arg_node, ast.Call) and isinstance(arg_node.func, ast.Attribute):
            if arg_node.func.attr == 'format':
                return "use of '.format()' with variables"

        if isinstance(arg_node, ast.Name):
            if arg_node.id not in {'True', 'False', 'None'}:
                return f"direct variable '{arg_node.id}' (unvalidated)"
        
        # Se não for literal e não for um padrão conhecido, ainda é suspeito
        # mas podemos retornar None por enquanto para reduzir falsos positivos
        # ou um padrão genérico:
        # return "complex variable" 
        return None 

    def _has_safe_parameters(self, node: ast.Call) -> bool:
        if len(node.args) >= 2:
            return True
        if len(node.args) == 1 and len(node.keywords) > 0:
             return True
        if any(kw.arg in {'params', 'parameters', 'args'} for kw in node.keywords):
            return True
        return False

    def visit_Call(self, node: ast.Call):
        function_name = self._get_function_name(node)

        if function_name in self.risky_function_names:
            if self.vulnerability_type == 'SQL Injection' and self._has_safe_parameters(node):
                self.generic_visit(node)
                return
            
            all_args = node.args + [kw.value for kw in node.keywords]
            
            for arg in all_args:
                vulnerable_pattern = self._check_argument_for_injection(arg)
                if vulnerable_pattern:
                    self.problems.append(Vulnerability(
                        line=node.lineno,
                        column=node.col_offset,
                        type=self.vulnerability_type,
                        function=function_name,
                        pattern=vulnerable_pattern,
                        description=f"Use of {vulnerable_pattern} in dangerous function '{function_name}'.",
                        severity="HIGH",
                        confidence="MEDIUM",
                        category="A03"  # Categoria de Injeção
                    ))
                    break 
        
        self.generic_visit(node)


# ===================== SPECIALIZED ANALYZERS =====================

class SQLInjectionAnalyzer(BaseInjectionAnalyzer):
    risky_function_names = {'execute', 'executemany', 'query', 'raw'}
    vulnerability_type = 'SQL Injection'


class CommandInjectionAnalyzer(BaseInjectionAnalyzer):
    risky_function_names = {'system', 'run', 'Popen', 'call', 'check_output', 'check_call', 'popen'}
    vulnerability_type = 'Command Injection'


class CodeEvaluationAnalyzer(BaseInjectionAnalyzer):
    risky_function_names = {'eval', 'exec', 'compile', '__import__'}
    vulnerability_type = 'Code Injection'


class LDAPInjectionAnalyzer(BaseInjectionAnalyzer):
    risky_function_names = {
        'search', 'search_st', 'search_ext', 'search_ext_s',
        'simple_bind_s', 'bind_s', 'modify_s', 'add_s', 'delete_s',
        'FindAll', 'FindOne', 'FindByIdentity'
    }
    vulnerability_type = 'LDAP Injection'


class NoSQLInjectionAnalyzer(BaseInjectionAnalyzer):
    risky_function_names = {
        'find', 'find_one', 'find_one_and_delete', 'find_one_and_replace',
        'delete_one', 'delete_many', 'update_one', 'update_many',
        'replace_one', 'aggregate', 'count_documents'
    }
    vulnerability_type = 'NoSQL Injection'

    def _is_likely_nosql(self, node: ast.Call) -> bool:
        """Verifica se a chamada parece ser de NoSQL (ex: db.find, collection.find)"""
        if not isinstance(node.func, ast.Attribute):
            return False
        
        obj_name = self._get_full_obj_name(node.func.value)
        return obj_name in {'db', 'collection', 'client'} or 'mongo' in obj_name

    def visit_Call(self, node: ast.Call):
        function_name = self._get_function_name(node)
        
        if function_name not in self.risky_function_names:
            self.generic_visit(node)
            return
        
        if not self._is_likely_nosql(node):
            self.generic_visit(node)
            return

        if node.args:
            filter_arg = node.args[0]
            
            if isinstance(filter_arg, ast.Dict):
                for i, key in enumerate(filter_arg.keys):
                    if key is not None and isinstance(key, ast.Constant) and key.value == "$where":
                        value_node = filter_arg.values[i]
                        vulnerable_pattern = self._check_argument_for_injection(value_node)
                        if vulnerable_pattern:
                            self.problems.append(Vulnerability(
                                line=node.lineno,
                                column=node.col_offset,
                                type=self.vulnerability_type,
                                function=function_name,
                                pattern=f"$where operator with {vulnerable_pattern}",
                                description=f"NoSQL $where operator vulnerable to injection.",
                                severity="HIGH",
                                confidence="MEDIUM",
                                category="A03"
                            ))
                            break
            else:
                vulnerable_pattern = self._check_argument_for_injection(filter_arg)
                if vulnerable_pattern:
                    self.problems.append(Vulnerability(
                        line=node.lineno,
                        column=node.col_offset,
                        type=self.vulnerability_type,
                        function=function_name,
                        pattern=vulnerable_pattern,
                        description=f"NoSQL query filter using {vulnerable_pattern}.",
                        severity="HIGH",
                        confidence="MEDIUM",
                        category="A03"
                    ))
        
        self.generic_visit(node)


class TemplateInjectionAnalyzer(BaseInjectionAnalyzer):
    risky_function_names = {'Template', 'render_template_string', 'from_string'}
    vulnerability_type = 'Template Injection (SSTI)'


class XPathInjectionAnalyzer(BaseInjectionAnalyzer):
    risky_function_names = {'xpath', 'find', 'findall', 'iterfind', 'XPath'}
    vulnerability_type = 'XPath Injection'

    def _is_likely_xpath(self, node: ast.Call) -> bool:
        """
        Eng: Checks if the call seems to be XPath (e.g., root.find, tree.xpath)    
        Pt:Verifica se a chamada parece ser de XPath (ex: root.find, tree.xpath)
        """
        if not isinstance(node.func, ast.Attribute):
            return False
        
        obj_name = self._get_full_obj_name(node.func.value)
        return obj_name in {'root', 'tree', 'element'} or 'xml' in obj_name or 'ET' in obj_name

    def visit_Call(self, node: ast.Call):
        function_name = self._get_function_name(node)
        
        if function_name not in self.risky_function_names:
            self.generic_visit(node)
            return

        if not self._is_likely_xpath(node):
            self.generic_visit(node)
            return
        
        super().visit_Call(node)


class XMLInjectionAnalyzer(BaseInjectionAnalyzer):
    risky_function_names = {'parse', 'fromstring', 'XML', 'XMLParser', 'iterparse'}
    vulnerability_type = 'XML Injection / XXE'

    def visit_Call(self, node: ast.Call):
        function_name = self._get_function_name(node)
        
        if function_name == 'XMLParser':
            is_safe = False
            for kw in node.keywords:
                if kw.arg == 'resolve_entities':
                    if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        self.problems.append(Vulnerability(
                            line=node.lineno,
                            column=node.col_offset,
                            type='XXE Vulnerability',
                            function=function_name,
                            pattern='resolve_entities=True',
                            description="XML parser configured to resolve external entities (XXE risk).",
                            severity="HIGH",
                            confidence="HIGH",
                            category="A03"
                        ))
                    elif isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        is_safe = True
            
            if is_safe:
                self.generic_visit(node)
                return

        if function_name in {'fromstring', 'parse'}:
            if any(kw.arg == 'parser' for kw in node.keywords):
                self.generic_visit(node)
                return 

        super().visit_Call(node)


class HeaderInjectionAnalyzer(BaseInjectionAnalyzer):
    vulnerability_type = 'Header Injection (CRLF)'

    def _is_header_object(self, node: ast.AST) -> bool:
        """
        Eng:Checks if the node is 'headers', 'response.headers', etc.
        Pt:Verifica se o nó é 'headers', 'response.headers', etc.
        """
        if isinstance(node, ast.Name) and node.id in {'response', 'headers', 'request'}:
            return True
        if isinstance(node, ast.Attribute) and node.attr == 'headers':
            if isinstance(node.value, ast.Name) and node.value.id == 'response':
                return True
        return False

    def visit_Subscript(self, node: ast.Subscript):
        if isinstance(node.ctx, ast.Store) and self._is_header_object(node.value):
            parent = getattr(node, '_parent', None)
            if isinstance(parent, ast.Assign):
                for target in parent.targets:
                    if target == node:
                        vulnerable_pattern = self._check_argument_for_injection(parent.value)
                        if vulnerable_pattern:
                            self.problems.append(Vulnerability(
                                line=node.lineno,
                                column=node.col_offset,
                                type=self.vulnerability_type,
                                function='header assignment',
                                pattern=vulnerable_pattern,
                                description=f"HTTP header set using {vulnerable_pattern}.",
                                severity="MEDIUM",
                                confidence="MEDIUM",
                                category="A03"
                            ))
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        for child in ast.walk(node):
            child._parent = node
        self.generic_visit(node)

# Faz parte da A09 mas ainda é do tipo injection 
class LogInjectionAnalyzer(BaseInjectionAnalyzer):
    risky_function_names = {'debug', 'info', 'warning', 'warn', 'error', 'critical', 'log', 'exception'}
    vulnerability_type = 'Log Injection'
   