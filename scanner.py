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
        """ Eng: Extracts the function name from a call node.
            Pt: Extrai o nome da função de um nó de chamada."""
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        if isinstance(node.func, ast.Name):
            return node.func.id
        return ""

    def _check_argument_for_injection(self, arg_node: ast.AST) -> str | None:
        """
        Eng: Checks an argument node and returns the vulnerability pattern
        found, or None if it is considered safe. It is RECURSIVE.
        Pt: Verifica um nó de argumento e retorna o padrão de vulnerabilidade
        encontrado, ou None se for considerado seguro. É RECURSIVO.
        """
        # f-string with variables
        if isinstance(arg_node, ast.JoinedStr):
            if any(isinstance(val, ast.FormattedValue) for val in arg_node.values):
                return "f-string with variables"
            return None 

        # Concatenation with '+' or formatting with '%'
        if isinstance(arg_node, ast.BinOp) and (isinstance(arg_node.op, ast.Add) or isinstance(arg_node.op, ast.Mod)):
            # Recursive check: the danger might be on one side of the operation
            left_check = self._check_argument_for_injection(arg_node.left)
            right_check = self._check_argument_for_injection(arg_node.right)
            if left_check or right_check:
                return left_check or right_check
            
           
            return "string concatenation with '+' or '%'"

        # Use of .format()
        if isinstance(arg_node, ast.Call) and isinstance(arg_node.func, ast.Attribute) and arg_node.func.attr == 'format':
            return "use of '.format()'"
        
        return None

    def visit_Call(self, node: ast.Call):
        """
        Eng: Visits each function call and applies the detection logic to ALL
        its arguments.
        Pt: Visita cada chamada de função e aplica a lógica de detecção a todos
        """
        function_name = self._get_function_name(node)

        if function_name in self.risky_function_names:
            # List of all arguments to check (positional and keyword)
            all_args = node.args + [kw.value for kw in node.keywords]
            
            for arg in all_args:
                vulnerable_pattern = self._check_argument_for_injection(arg)
                if vulnerable_pattern:
                    self.problems.append({
                        'line': node.lineno,
                        'type': self.vulnerability_type,
                        'description': f"Use of {vulnerable_pattern} in dangerous function '{function_name}'."
                    })
                    
                    break 
        
        
        self.generic_visit(node)



class SQLInjectionAnalyzer(BaseAnalyzer):
    """Eng: Defines the risk functions for SQL Injection.
       Pt: Define as funções de risco para Injeção SQL.
    """
    risky_function_names = {'execute', 'executemany', 'query'}
    vulnerability_type = 'SQL Injection'

class CommandInjectionAnalyzer(BaseAnalyzer):
    """Eng: defines the risk functions for Command Injection.
       Pt: Define as funções de risco para Injeção de Comandos."""
    risky_function_names = {'system', 'run', 'Popen', 'call'}
    vulnerability_type = 'Command Injection'

class CodeEvaluationAnalyzer(BaseAnalyzer):
    """Eng: Detects the dangerous use of eval() and exec().
       Pt: Detecta o uso perigoso de eval() e exec()."""
    risky_function_names = {'eval', 'exec'}
    vulnerability_type = 'Code Injection'


# ----------------------- ANALYSIS ----------------------------
def analyze_file(file_path: str) -> List[Dict[str, Any]]:
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            code = file.read()
            code_ast = ast.parse(code)
    except (FileNotFoundError, SyntaxError) as e:
        print(f"Error processing file: {e}")
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
def show_results(problems: List[Dict[str, Any]]):
    if not problems:
        print(" No problems found")
        return
    
    problems.sort(key=lambda p: p['line'])
    print(f"Found {len(problems)} problems:")
    for i, problem in enumerate(problems, 1):
        print(f"\nProblem #{i}")
        print(f"  Line:        {problem['line']}")
        print(f"  Type:        {problem['type']}")
        print(f"  Description: {problem['description']}")


# ----------------------------------------------------
if __name__ == "__main__":
    file_to_analyze = "teste.py" 
    
    print(f"--- Analyzing file: {file_to_analyze} ---")
    found_problems = analyze_file(file_to_analyze)
    print("-" * 40)
    
    show_results(found_problems)