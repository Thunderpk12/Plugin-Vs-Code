import ast
from typing import List, Dict, Any, Set, Optional
from dataclasses import dataclass, field
import json
# ===================== DATA STRUCTURES =====================

@dataclass
class Vulnerability:
    """
    Eng: Data structure to represent a vulnerability
    Pt:Estrutura de dados para representar uma vulnerabilidade
    """
    line: int
    column: int
    type: str
    function: str
    pattern: str
    description: str
    severity: str = "MEDIUM"  # HIGH, MEDIUM, LOW
    confidence: str = "MEDIUM"  # HIGH, MEDIUM, LOW
    tainted: bool = False  # Se foi confirmado por taint analysis
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'line': self.line,
            'column': self.column,
            'type': self.type,
            'function': self.function,
            'pattern': self.pattern,
            'description': self.description,
            'severity': self.severity,
            'confidence': self.confidence,
            'tainted': self.tainted
        }


# ===================== TAINT ANALYSIS =====================

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
        """Obtém o nome qualificado completo (ex: 'request.args.get')"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            parent = self._get_full_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        elif isinstance(node, ast.Call):
            return self._get_full_name(node.func)
        return ""
    
    def _is_source(self, node: ast.AST) -> bool:
        """Verifica se o nó é uma source (origem não confiável)"""
        if isinstance(node, ast.Call):
            func_name = self._get_full_name(node.func)
            return any(source in func_name for source in self.SOURCES)
        
        if isinstance(node, ast.Attribute):
            full_name = self._get_full_name(node)
            return any(source in full_name for source in self.SOURCES)
        
        return False
    
    def _is_sanitizer(self, node: ast.AST) -> bool:
        """Verifica se o nó é um sanitizer"""
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
        """Verifica se um nó contém dados tainted"""
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
        """Rastreia atribuições para propagar taint"""
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
        """Marca linhas onde dados tainted são usados e limpa vars em sanitizers"""
        
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
        """Verifica se uma linha específica tem dados tainted"""
        return line in self.tainted_lines


# ===================== BASE ANALYZER (Original) =====================

class BaseAnalyzer(ast.NodeVisitor):
    """Classe base para detecção de padrões de injeção"""
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
        """Helper para obter o nome do objeto (ex: 'db' em 'db.users.find')"""
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
                        confidence="MEDIUM"
                    ))
                    break 
        
        self.generic_visit(node)


# ===================== SPECIALIZED ANALYZERS =====================

class SQLInjectionAnalyzer(BaseAnalyzer):
    risky_function_names = {'execute', 'executemany', 'query', 'raw'}
    vulnerability_type = 'SQL Injection'


class CommandInjectionAnalyzer(BaseAnalyzer):
    risky_function_names = {'system', 'run', 'Popen', 'call', 'check_output', 'check_call', 'popen'}
    vulnerability_type = 'Command Injection'


class CodeEvaluationAnalyzer(BaseAnalyzer):
    risky_function_names = {'eval', 'exec', 'compile', '__import__'}
    vulnerability_type = 'Code Injection'


class LDAPInjectionAnalyzer(BaseAnalyzer):
    risky_function_names = {
        'search', 'search_st', 'search_ext', 'search_ext_s',
        'simple_bind_s', 'bind_s', 'modify_s', 'add_s', 'delete_s',
        'FindAll', 'FindOne', 'FindByIdentity'
    }
    vulnerability_type = 'LDAP Injection'


class NoSQLInjectionAnalyzer(BaseAnalyzer):
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
                                confidence="MEDIUM"
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
                        confidence="MEDIUM"
                    ))
        
        self.generic_visit(node)


class TemplateInjectionAnalyzer(BaseAnalyzer):
    risky_function_names = {'Template', 'render_template_string', 'from_string'}
    vulnerability_type = 'Template Injection (SSTI)'


class XPathInjectionAnalyzer(BaseAnalyzer):
    risky_function_names = {'xpath', 'find', 'findall', 'iterfind', 'XPath'}
    vulnerability_type = 'XPath Injection'

    def _is_likely_xpath(self, node: ast.Call) -> bool:
        """Verifica se a chamada parece ser de XPath (ex: root.find, tree.xpath)"""
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


class XMLInjectionAnalyzer(BaseAnalyzer):
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
                            confidence="HIGH"
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


class HeaderInjectionAnalyzer(BaseAnalyzer):
    vulnerability_type = 'Header Injection (CRLF)'

    def _is_header_object(self, node: ast.AST) -> bool:
        """Verifica se o nó é 'headers', 'response.headers', etc."""
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
                                confidence="MEDIUM"
                            ))
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        for child in ast.walk(node):
            child._parent = node
        self.generic_visit(node)


class LogInjectionAnalyzer(BaseAnalyzer):
    risky_function_names = {'debug', 'info', 'warning', 'warn', 'error', 'critical', 'log', 'exception'}
    vulnerability_type = 'Log Injection'


# ===================== MAIN ANALYSIS FUNCTION =====================

def analyze_file(file_path: str, enable_taint_analysis: bool = True) -> List[Dict[str, Any]]:
    """
    Eng: Analyzes a Python file for security vulnerabilities.
    Pt: Analisa um arquivo Python em busca de vulnerabilidades de segurança.
    
    Args:
        file_path: Caminho do arquivo a analisar
        enable_taint_analysis: Se True, usa taint analysis para refinar resultados
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            code = file.read()
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return []
    except Exception as e:
        print(f"Error reading file: {e}")
        return []

    try:
        code_ast = ast.parse(code, filename=file_path)
    except SyntaxError as e:
        print(f"Syntax error in file (line {e.lineno}): {e.msg}")
        return []
    
    
    print("Phase 1: Pattern-based detection...")
    analyzers = [
        SQLInjectionAnalyzer(),
        CommandInjectionAnalyzer(),
        CodeEvaluationAnalyzer(),
        LDAPInjectionAnalyzer(),
        NoSQLInjectionAnalyzer(),
        TemplateInjectionAnalyzer(),
        XPathInjectionAnalyzer(),
        XMLInjectionAnalyzer(),
        HeaderInjectionAnalyzer(),
        LogInjectionAnalyzer(),
    ]

    all_problems = []
    for analyzer in analyzers:
        analyzer.visit(code_ast)
        all_problems.extend(analyzer.problems)
    
    print(f"   Found {len(all_problems)} potential issues")
    
    # Taint analysis (opcional)
    if enable_taint_analysis:
        print("Phase 2: Taint analysis refinement...")
        taint_analyzer = TaintAnalyzer()
        taint_analyzer.visit(code_ast)
        
        refined_problems = []
        tainted_count = 0
        low_conf_count = 0
        pattern_conf_count = 0 # CORREÇÃO: Novo contador
        
        for vuln in all_problems:
            is_tainted = taint_analyzer.is_line_tainted(vuln.line)
            
            is_taint_dependent = "variable" in vuln.pattern or \
                                 "f-string" in vuln.pattern or \
                                 "concatenation" in vuln.pattern or \
                                 "format" in vuln.pattern

            if is_tainted:
                vuln.confidence = "HIGH"
                vuln.tainted = True
                refined_problems.append(vuln)
                tainted_count += 1
            elif not is_taint_dependent:
                # Ex: XXE estático
                refined_problems.append(vuln)
                pattern_conf_count += 1 # CORREÇÃO: Contar
            else:
                vuln.confidence = "LOW"
                vuln.description += " (Taint not confirmed - review manually)"
                refined_problems.append(vuln)
                low_conf_count += 1
        
        print(f"   {tainted_count} confirmed with taint analysis")
        # CORREÇÃO: Novo sumário
        print(f"   {pattern_conf_count} confirmed by static pattern (e.g., XXE)")
        print(f"   {low_conf_count} marked as low confidence (manual review needed)")
        
        return [v.to_dict() for v in refined_problems]
    
    return [v.to_dict() for v in all_problems]


# ===================== RESULTS PRESENTATION =====================

def show_results(problems: List[Dict[str, Any]], verbose: bool = True, show_low_confidence: bool = True):
    """Exibe os resultados da análise"""
    if not problems:
        print("No security problems found")
        return
    
    if not show_low_confidence:
        problems = [p for p in problems if p['confidence'] != 'LOW']
    
    if not problems:
        print("No high/medium-confidence security problems found")
        return
    
    problems.sort(key=lambda p: (
        {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}.get(p['severity'], 9),
        {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}.get(p['confidence'], 9),
        p['line'],
        p['column']
    ))
    
    high_conf = sum(1 for p in problems if p['confidence'] == 'HIGH')
    medium_conf = sum(1 for p in problems if p['confidence'] == 'MEDIUM')
    low_conf = sum(1 for p in problems if p['confidence'] == 'LOW')
    
    print(f"\n{'='*70}")
    print(f"Found {len(problems)} potential vulnerabilities (showing { 'all' if show_low_confidence else 'medium/high confidence' })")
    print(f"   High confidence: {high_conf}")
    print(f"   Medium confidence: {medium_conf}")
    print(f"   Low confidence: {low_conf}")
    print(f"{'='*70}\n")
    
    if verbose:
        for i, problem in enumerate(problems, 1):
            severity_tag = problem['severity']
            confidence_tag = problem['confidence']
            
            print(f"Problem #{i} [{severity_tag}] [{confidence_tag}]")
            print(f"    Location:    Line {problem['line']}, Column {problem['column']}")
            print(f"    Type:        {problem['type']}")
            print(f"    Function:    {problem['function']}()")
            print(f"    Pattern:     {problem['pattern']}")
            print(f"    Description: {problem['description']}")
            if problem.get('tainted'):
                print(f"    Confirmed by taint analysis")
            print()
    else:
       
        for problem in problems:
            print(f"L{problem['line']}: [{problem['severity']}/{problem['confidence']}] {problem['type']} in {problem['function']}()")


def export_json(problems: List[Dict[str, Any]], output_file: str = "analysis_results.json"):
    """Exporta resultados para JSON"""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(problems, f, indent=2, ensure_ascii=False)
        print(f"\nResults exported to: {output_file}")
    except Exception as e:
        print(f"Error exporting JSON: {e}")


# ==========================================

if __name__ == "__main__":
    
   
    file_to_analyze = "vulneravel.py"
    enable_taint = True
    export_file = None 
    hide_low = False
    brief_output = False
    
    print(f"\nAnalyzing file: {file_to_analyze}")
    print(f"   Taint analysis: {'enabled' if enable_taint else 'disabled'}")
    print()
    
    found_problems = analyze_file(file_to_analyze, enable_taint_analysis=enable_taint)
    
    show_results(found_problems, verbose=not brief_output, show_low_confidence=not hide_low)
    
    # if export_file:
    #     export_json(found_problems, export_file)