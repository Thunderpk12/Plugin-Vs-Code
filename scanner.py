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
        # Strings literais puras (sem interpolação)
        if isinstance(node, ast.Constant):
            return True
        
        # Listas/tuplas/dicts de literais também são seguros
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
        # Ignorar literais seguros
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
            
            # Se ambos os lados são literais, é seguro
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
        # Verifica se há mais de um argumento 
        # Exemplo: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        return len(node.args) >= 2 or any(kw.arg in {'params', 'parameters', 'args'} for kw in node.keywords)

    def visit_Call(self, node: ast.Call):
        """
        Eng: Visits each function call and applies the detection logic.
        Pt: Visita cada chamada de função e aplica a lógica de detecção.
        """
        function_name = self._get_function_name(node)

        if function_name in self.risky_function_names:
            # Para SQL, verificar se usa parametrização segura
            if self.vulnerability_type == 'SQL Injection' and self._has_safe_parameters(node):
                # Tem parâmetros separados - provavelmente seguro
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
       Pt: Deteta vulnerabilidades de Injeção LDAP em consultas a deretórios"""
    risky_function_names = {
        'search', 'search_st','search_ext','search_ext_s',
        'simple_bind_s', 'modify_s','FindAll','FindOne', 'FindeByIdentity'}
    vulnerability_type = 'LDAP Injection'

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
        print(" No security problems found")
        return
    
    problems.sort(key=lambda p: (p['line'], p['column']))
    
    if verbose:
        print("\n" + "="*60)
        for i, problem in enumerate(problems, 1):
            
            print(f"\n Problem #{i} ")
            print(f"  Location:    Line {problem['line']}, Column {problem['column']}")
            print(f"  Type:        {problem['type']}")
            print(f"  Function:    {problem['function']}()")
            print(f"  Pattern:     {problem['pattern']}")
            print(f"  Description: {problem['description']}")
        print("="*60)


def export_json(problems: List[Dict[str, Any]], output_file: str = "analysis_results.json"):
    """
    Eng: Exports results to JSON.
    Pt: Exporta resultados para JSON .
    """
    import json
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(problems, f, indent=2, ensure_ascii=False)
        print(f"\n Results exported to: {output_file}")
    except Exception as e:
        print(f"Error exporting JSON: {e}")


# ----------------------------------------------------
if __name__ == "__main__":
    import sys
    
    file_to_analyze = sys.argv[1] if len(sys.argv) > 1 else "teste.py"
    
    print(f"\n Analyzing file: {file_to_analyze}")
    
    found_problems = analyze_file(file_to_analyze)
    show_results(found_problems, verbose=True)
    
    # Exportar para JSON (opcional) 
    #if found_problems:
    #   export_json(found_problems)