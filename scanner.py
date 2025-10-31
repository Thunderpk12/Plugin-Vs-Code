import ast
from typing import List, Dict, Any

class BaseAnalyzer(ast.NodeVisitor):
    """
    Eng: Base class containing the shared logic for finding vulnerabilities
    based on string injection.
    Pt: Classe base contendo a lógica compartilhada para encontrar vulnerabilidades
    baseadas em injeção de strings.
    """
    risky_function_names: set = set()
    vulnerability_type: str = "GENERIC_INJECTION"

    def __init__(self):
        self.problems: List[Dict[str, Any]] = []

    def _get_function_name(self, node: ast.Call) -> str:
        """Eng: Extracts the function name from a call node.
           Pt: Extrai o nome da função de um nó de chamada."""
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        if isinstance(node.func, ast.Name):
            return node.func.id
        return ""

    def _is_literal_safe(self, node: ast.AST) -> bool:
        """
        Eng: Checks if a node is a safe literal (string, number, bool, None, etc.)
        Pt: Verifica se um nó é um literal seguro (string, número, bool, None, etc.)
        """
        if isinstance(node, ast.Constant):
            return True
        
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return all(self._is_literal_safe(elt) for elt in node.elts)
        
        if isinstance(node, ast.Dict):
            return all(self._is_literal_safe(k) and self._is_literal_safe(v) 
                       for k, v in zip(node.keys, node.values))
        
        return False

    def _check_argument_for_injection(self, arg_node: ast.AST) -> str | None:
        """
        Eng: Checks an argument node and returns the vulnerability pattern
        found, or None if it is considered safe. It is recursive.
        Pt: Verifica um nó de argumento e retorna o padrão de vulnerabilidade
        encontrado, ou None se for considerado seguro. É recursivo.
        """
        if self._is_literal_safe(arg_node):
            return None

        # f-string com variáveis
        if isinstance(arg_node, ast.JoinedStr):
            if any(isinstance(val, ast.FormattedValue) for val in arg_node.values):
                return "f-string with variables"
            return None 

        # Concatenação com '+' ou formatação com '%'
        if isinstance(arg_node, ast.BinOp):
            left_check = self._check_argument_for_injection(arg_node.left)
            right_check = self._check_argument_for_injection(arg_node.right)
            
            if left_check or right_check:
                return left_check or right_check
            
            if self._is_literal_safe(arg_node.left) and self._is_literal_safe(arg_node.right):
                return None
                  
            if isinstance(arg_node.op, (ast.Add, ast.Mod)):
                return "string concatenation/formatting with variables"

        # Uso de .format()
        if isinstance(arg_node, ast.Call) and isinstance(arg_node.func, ast.Attribute):
            if arg_node.func.attr == 'format':
                return "use of '.format()' with variables"

        # Uso direto de variáveis
        if isinstance(arg_node, ast.Name):
            if arg_node.id not in {'True', 'False', 'None'}:
                return f"direct variable '{arg_node.id}' (unvalidated)"

        # Acesso a dicionário/lista
        if isinstance(arg_node, ast.Subscript):
            return "subscript access (dict/list indexing)"
                  
        # Acesso a atributo de objeto
        if isinstance(arg_node, ast.Attribute):
            return "attribute access (object field)"
        
        return None

    def _has_safe_parameters(self, node: ast.Call) -> bool:
        """
        Eng: Checks if the call uses parameterized queries (safe pattern).
        Pt: Verifica se a chamada usa queries parametrizadas (padrão seguro).
        """
        return len(node.args) >= 2 or any(kw.arg in {'params', 'parameters', 'args'} for kw in node.keywords)

    def visit_Call(self, node: ast.Call):
        """
        Eng: Visits each function call and applies the detection logic.
        Pt: Visita cada chamada de função e aplica a lógica de detecção.
        """
        function_name = self._get_function_name(node)

        if function_name in self.risky_function_names:
            if self.vulnerability_type == 'SQL Injection' and self._has_safe_parameters(node):
                self.generic_visit(node)
                return
            
            all_args = node.args + [kw.value for kw in node.keywords]
            
            for arg in all_args:
                vulnerable_pattern = self._check_argument_for_injection(arg)
                if vulnerable_pattern:
                    self.problems.append({
                        'line': node.lineno,
                        'column': node.col_offset,
                        'type': self.vulnerability_type,
                        'function': function_name,
                        'pattern': vulnerable_pattern,
                        'description': f"Use of {vulnerable_pattern} in dangerous function '{function_name}'."
                    })
                    break 
        
        self.generic_visit(node)


class SQLInjectionAnalyzer(BaseAnalyzer):
    """Eng: Defines the risk functions for SQL Injection.
       Pt: Define as funções de risco para Injeção SQL."""
    risky_function_names = {'execute', 'executemany', 'query', 'raw'}
    vulnerability_type = 'SQL Injection'


class CommandInjectionAnalyzer(BaseAnalyzer):
    """Eng: Defines the risk functions for Command Injection.
       Pt: Define as funções de risco para Injeção de Comandos."""
    risky_function_names = {
        'system', 'run', 'Popen', 'call', 
        'check_output', 'check_call', 'popen'  
    }
    vulnerability_type = 'Command Injection'


class CodeEvaluationAnalyzer(BaseAnalyzer):
    """Eng: Detects the dangerous use of eval() and exec().
       Pt: Detecta o uso perigoso de eval() e exec()."""
    risky_function_names = {'eval', 'exec', 'compile', '__import__'}  
    vulnerability_type = 'Code Injection'


class LDAPInjectionAnalyzer(BaseAnalyzer):
    """Eng: Defines and detects the risk functions for LDAP Injection.
       Pt: Detecta vulnerabilidades de Injeção LDAP em consultas a diretórios"""
    risky_function_names = {
        'search', 'search_st', 'search_ext', 'search_ext_s',
        'simple_bind_s', 'bind_s', 'modify_s', 'add_s', 'delete_s',
        'FindAll', 'FindOne', 'FindByIdentity'
    }
    vulnerability_type = 'LDAP Injection'

    def _has_safe_parameters(self, node: ast.Call) -> bool:
        """
        Eng: Checks if the call uses proper LDAP escaping functions. 
        Pt: Verifica se a chamada usa funções de escape LDAP apropriadas.
        """
        for arg in node.args:
            if isinstance(arg, ast.Call):
                func_name = self._get_function_name(arg)
                if func_name in {'escape_filter_chars', 'escape_dn_chars',
                                 'ldap_escape', 'sanitize_ldap'}:
                    return True
        return False


class NoSQLInjectionAnalyzer(BaseAnalyzer):
    """
    Eng: Detects NoSQL Injection vulnerabilities, especially in MongoDB.
    Pt: Detecta vulnerabilidades de Injeção NoSQL, especialmente em MongoDB.
    """
    risky_function_names = {
        'find', 'find_one', 'find_one_and_delete', 'find_one_and_replace',
        'delete_one', 'delete_many', 'update_one', 'update_many',
        'replace_one', 'aggregate', 'count_documents'
    }
    vulnerability_type = 'NoSQL Injection'

    def visit_Call(self, node: ast.Call):
        function_name = self._get_function_name(node)
        
        if function_name in self.risky_function_names:
            if node.args:
                filter_arg = node.args[0]
                
                # Padrão perigoso: {"$where": f"this.name == '{user_input}'"}
                if isinstance(filter_arg, ast.Dict):
                    for i, key in enumerate(filter_arg.keys):
                        if isinstance(key, ast.Constant) and key.value == "$where":
                            value_node = filter_arg.values[i]
                            vulnerable_pattern = self._check_argument_for_injection(value_node)
                            if vulnerable_pattern:
                                self.problems.append({
                                    'line': node.lineno,
                                    'column': node.col_offset,
                                    'type': self.vulnerability_type,
                                    'function': function_name,
                                    'pattern': f"$where operator with {vulnerable_pattern}",
                                    'description': f"NoSQL $where operator vulnerable to injection via {vulnerable_pattern}."
                                })
                                break
                
                # Verificar se o filtro inteiro é uma variável não validada
                else:
                    vulnerable_pattern = self._check_argument_for_injection(filter_arg)
                    if vulnerable_pattern:
                        self.problems.append({
                            'line': node.lineno,
                            'column': node.col_offset,
                            'type': self.vulnerability_type,
                            'function': function_name,
                            'pattern': vulnerable_pattern,
                            'description': f"NoSQL query filter using {vulnerable_pattern}."
                        })
        
        self.generic_visit(node)


class TemplateInjectionAnalyzer(BaseAnalyzer):
    """
    Eng: Detects Server-Side Template Injection (SSTI) in Jinja2, Django, etc.
    Pt: Detecta Injeção de Templates (SSTI) em Jinja2, Django, etc.
    
  """
    risky_function_names = {
        'Template',  # Jinja2
        'render_template_string',  # Flask
        'from_string',  # Jinja2 Environment
        'render',  # Django (quando recebe string diretamente)
    }
    vulnerability_type = 'Template Injection (SSTI)'

    def visit_Call(self, node: ast.Call):
        function_name = self._get_function_name(node)
        
        # Template() ou render_template_string() com input do usuário
        if function_name in self.risky_function_names:
            if node.args:
                template_source = node.args[0]
                vulnerable_pattern = self._check_argument_for_injection(template_source)
                
                if vulnerable_pattern:
                    self.problems.append({
                        'line': node.lineno,
                        'column': node.col_offset,
                        'type': self.vulnerability_type,
                        'function': function_name,
                        'pattern': vulnerable_pattern,
                        'description': f"Template created from {vulnerable_pattern} - possible SSTI."
                    })
        
        self.generic_visit(node)


class XPathInjectionAnalyzer(BaseAnalyzer):
    """
    Eng: Detects XPath Injection in XML queries.
    Pt: Detecta Injeção XPath em consultas XML.
    
    Exemplo perigoso:
        xpath = f"//user[@name='{username}']"
        root.xpath(xpath)
    """
    risky_function_names = {
        'xpath',  # lxml
        'find',  # ElementTree com XPath
        'findall',
        'iterfind',
        'XPath',  # lxml.etree.XPath()
    }
    vulnerability_type = 'XPath Injection'


class XMLInjectionAnalyzer(BaseAnalyzer):
    """
    Eng: Detects XML External Entity (XXE) and XML Injection vulnerabilities.
    Pt: Detecta vulnerabilidades XXE e Injeção XML.
    
   
    """
    risky_function_names = {
        'parse',  # xml.etree / lxml
        'fromstring',
        'XML',
        'XMLParser',
        'iterparse',
    }
    vulnerability_type = 'XML Injection / XXE'

    def visit_Call(self, node: ast.Call):
        function_name = self._get_function_name(node)
        
        if function_name in self.risky_function_names:
            # Verificar se XMLParser tem resolve_entities=True (perigoso)
            if function_name == 'XMLParser':
                for kw in node.keywords:
                    if kw.arg == 'resolve_entities':
                        if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            self.problems.append({
                                'line': node.lineno,
                                'column': node.col_offset,
                                'type': 'XXE Vulnerability',
                                'function': function_name,
                                'pattern': 'resolve_entities=True',
                                'description': "XML parser configured to resolve external entities (XXE risk)."
                            })
            
            # Verificar se o XML vem de input não validado
            if node.args:
                xml_source = node.args[0]
                vulnerable_pattern = self._check_argument_for_injection(xml_source)
                
                if vulnerable_pattern:
                    self.problems.append({
                        'line': node.lineno,
                        'column': node.col_offset,
                        'type': self.vulnerability_type,
                        'function': function_name,
                        'pattern': vulnerable_pattern,
                        'description': f"XML parsed from {vulnerable_pattern} without validation."
                    })
        
        self.generic_visit(node)


class HeaderInjectionAnalyzer(BaseAnalyzer):
    """
    Eng: Detects HTTP Header Injection (CRLF Injection).
    Pt: Detecta Injeção de Cabeçalhos HTTP (CRLF Injection).
    
    """
    vulnerability_type = 'Header Injection (CRLF)'

    def visit_Subscript(self, node: ast.Subscript):
        """Detecta response['Header'] = variavel"""
        if isinstance(node.ctx, ast.Store):
            # Verificar se é um objeto response/headers
            if isinstance(node.value, ast.Name):
                obj_name = node.value.id
                if obj_name in {'response', 'headers', 'request'}:
                    # Encontrar a atribuição pai
                    parent = getattr(node, '_parent', None)
                    if isinstance(parent, ast.Assign):
                        for target in parent.targets:
                            if target == node:
                                value = parent.value
                                vulnerable_pattern = self._check_argument_for_injection(value)
                                
                                if vulnerable_pattern:
                                    self.problems.append({
                                        'line': node.lineno,
                                        'column': node.col_offset,
                                        'type': self.vulnerability_type,
                                        'function': 'header assignment',
                                        'pattern': vulnerable_pattern,
                                        'description': f"HTTP header set using {vulnerable_pattern} - CRLF injection risk."
                                    })
        
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        """Marca os nós para rastreamento de contexto"""
        for child in ast.walk(node):
            child._parent = node
        self.generic_visit(node)


class LogInjectionAnalyzer(BaseAnalyzer):
    """
    Eng: Detects Log Injection vulnerabilities.
    Pt: Detecta vulnerabilidades de Injeção em Logs.
    
    Exemplo perigoso:
        logger.info(f"User logged in: {username}")  # username pode conter \n
        logging.error("Failed: " + user_input)
    """
    risky_function_names = {
        'debug', 'info', 'warning', 'warn', 'error', 'critical',
        'log', 'exception'
    }
    vulnerability_type = 'Log Injection'


# ----------------------- ANALYSIS ----------------------------
def analyze_file(file_path: str) -> List[Dict[str, Any]]:
    """
    Eng: Analyzes a Python file for security vulnerabilities.
    Pt: Analisa um arquivo Python em busca de vulnerabilidades de segurança.
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
    
    return all_problems


# -------------- RESULTS PRESENTATION ---------------
def show_results(problems: List[Dict[str, Any]], verbose: bool = True):
    """
    Eng: Displays analysis results.
    Pt: Exibe os resultados da análise.
    """
    if not problems:
        print("No security problems found")
        return
    
    problems.sort(key=lambda p: (p['line'], p['column']))
    
    print(f"\nFound {len(problems)} potential vulnerabilities:\n")
    print("="*70)
    
    if verbose:
        for i, problem in enumerate(problems, 1):
            print(f"\nProblem #{i}")
            print(f"   Location:    Line {problem['line']}, Column {problem['column']}")
            print(f"   Type:        {problem['type']}")
            print(f"   Function:    {problem['function']}()")
            print(f"   Pattern:     {problem['pattern']}")
            print(f"   Description: {problem['description']}")
    else:
        for problem in problems:
            print(f"Line {problem['line']}: {problem['type']} in {problem['function']}()")
    
    print("="*70)


def export_json(problems: List[Dict[str, Any]], output_file: str = "analysis_results.json"):
    """
    Eng: Exports results to JSON.
    Pt: Exporta resultados para JSON.
    """
    import json
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(problems, f, indent=2, ensure_ascii=False)
        print(f"\nResults exported to: {output_file}")
    except Exception as e:
        print(f"Error exporting JSON: {e}")


# ----------------------------------------------------
if __name__ == "__main__":
    import sys
    
    file_to_analyze = sys.argv[1] if len(sys.argv) > 1 else "teste.py"
    
    print(f"\nAnalyzing file: {file_to_analyze}")
    
    found_problems = analyze_file(file_to_analyze)
    show_results(found_problems, verbose=True)
    
    #if found_problems:
        #export_json(found_problems)