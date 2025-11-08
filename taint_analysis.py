"""
Eng:A03:2021 - Taint Analysis (Taint Analysis)

This module implements an enhanced taint analysis to track the flow of 
untrusted (tainted) data, including interprocedural flow and 
contextual sanitizers.
-----------------------------------------------------------
Pt:A03:2021 - Análise de Taint (Taint Analysis)

Este módulo implementa uma análise de taint melhorada para rastrear o fluxo 
de dados não confiáveis (tainted), incluindo fluxo interprocedural e 
sanitizers contextuais.
"""

import ast
from typing import Set, Dict, List, Optional, Tuple
from dataclasses import dataclass

@dataclass
class TaintInfo:
    """
    Eng: Detailed taint information.
    Pt: Informação detalhada sobre taint.
    """
    var_name: str
    source: str  #  Taint origin 
    line: int
    sanitized: bool = False
    sanitizer_used: Optional[str] = None

class TaintAnalyzer(ast.NodeVisitor):
    """
    Eng: Implements enhanced taint analysis with:
         - Interprocedural tracking
         - Contextual sanitizer detection
         - Propagation through data structures
    Pt: Implementa análise de taint melhorada com:
         - Rastreamento interprocedural
         - Detecção de sanitizers contextuais
         - Propagação através de estruturas de dados
    """
    
    # Origens de dados não confiáveis
    SOURCES = {
        'request.args', 'request.form', 'request.json', 'request.data',
        'request.args.get', 'request.form.get', 'request.json.get',
        'request.GET', 'request.POST', 'request.FILES', 'request.cookies',
        'input', 'raw_input', 'sys.argv', 'os.environ', 'os.environ.get',
        'socket.recv', 'urlopen', 'requests.get', 'requests.post',
    }
    
    # Sanitizers categorizados por contexto
    SQL_SANITIZERS = {
        'int', 'float', 'bool',
        'escape_string', 'quote_identifier',
        'sqlalchemy.text',  # Quando usado com bind parameters
    }
    
    COMMAND_SANITIZERS = {
        'shlex.quote', 'pipes.quote',
        'list',  # subprocess com list é mais seguro
    }
    
    HTML_SANITIZERS = {
        'html.escape', 'markupsafe.escape',
        'django.utils.html.escape',
        'bleach.clean',
    }
    
    GENERIC_SANITIZERS = {
        're.match', 're.search', 're.fullmatch',
        'ast.literal_eval',
        'json.loads', 'json.dumps',
    }
    
   
    #  Sanitizers fracos que não removem taint completamente
    WEAK_SANITIZERS = {
        'str.strip', 'str.replace', 'str.lower', 'str.upper',
    }
    
    def __init__(self):
        self.tainted_vars: Dict[str, TaintInfo] = {}
        self.clean_vars: Set[str] = set()
        self.tainted_lines: Dict[int, List[str]] = {}  # line -> [reasons]
        
        # Interprocedural tracking
        self.function_returns: Dict[str, bool] = {}  # func_name -> returns_tainted
        self.function_params: Dict[str, Set[int]] = {}  # func_name -> tainted_param_indices
        
        # Data structures
        self.tainted_containers: Dict[str, bool] = {}  # dict_name/list_name -> is_tainted
        
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
    
    def _is_source(self, node: ast.AST) -> Tuple[bool, str]:
        """
        Eng:Checks if the node is a source (untrusted origin). Returns (is_source, source_name).
        Pt:Verifica se o nó é uma source (origem não confiável). Retorna (is_source, source_name).
        """
        if isinstance(node, ast.Call):
            func_name = self._get_full_name(node.func)
            for source in self.SOURCES:
                if source in func_name:
                    return True, func_name
        
        if isinstance(node, ast.Attribute):
            full_name = self._get_full_name(node)
            for source in self.SOURCES:
                if source in full_name:
                    return True, full_name
        
        return False, ""
    
    def _get_sanitizer_strength(self, node: ast.AST, context: str = "generic") -> Tuple[bool, str, str]:
        """
        Eng: Checks if the node is a sanitizer and returns (is_sanitizer, sanitizer_name, strength).
             Strength: 'strong', 'weak', 'context'.
        Pt: Verifica se o nó é um sanitizer e retorna (is_sanitizer, sanitizer_name, strength).
             Strength: 'strong', 'weak', 'context'.
        """
        if not isinstance(node, ast.Call):
            return False, "", ""
        
        func_name = self._get_full_name(node.func)
        
        # Verificar sanitizers específicos do contexto
        if context == "sql":
            if any(san in func_name for san in self.SQL_SANITIZERS):
                return True, func_name, "strong"
        elif context == "command":
            if any(san in func_name for san in self.COMMAND_SANITIZERS):
                return True, func_name, "strong"
        elif context == "html":
            if any(san in func_name for san in self.HTML_SANITIZERS):
                return True, func_name, "strong"
        
        # Sanitizers genéricos
        if any(san in func_name for san in self.GENERIC_SANITIZERS):
            return True, func_name, "strong"
        
        # Sanitizers fracos
        if any(san in func_name for san in self.WEAK_SANITIZERS):
            return True, func_name, "weak"
        
        # Heurística: nomes que sugerem validação
        safe_words = ['validate', 'sanitize', 'clean', 'escape', 'quote', 'filter', 'whitelist']
        if any(word in func_name.lower() for word in safe_words):
            return True, func_name, "context"
        
        return False, "", ""
    
    def _is_tainted(self, node: ast.AST) -> Tuple[bool, str]:
        """
        Eng:Checks if a node contains tainted data. Returns (is_tainted, reason).
        Pt:Verifica se um nó contém dados tainted. Retorna (is_tainted, reason).
        """
        if isinstance(node, ast.Constant):
            return False, ""
        
        if isinstance(node, ast.Name):
            var_name = node.id
            if var_name in self.tainted_vars:
                info = self.tainted_vars[var_name]
                # Se estiver "sanitized", consideramos limpo para propagação
                if not info.sanitized: 
                    return True, f"tainted variable '{var_name}' from {info.source}"
            if var_name in self.tainted_containers:
                return True, f"tainted container '{var_name}'"
            return False, ""
        
        # Verificar se é source
        is_src, src_name = self._is_source(node)
        if is_src:
            return True, f"direct source: {src_name}"
        
        if isinstance(node, ast.Attribute):
            is_tainted, reason = self._is_tainted(node.value)
            if is_tainted:
                return True, reason
        
        if isinstance(node, ast.Subscript):
            # Container tainted contamina o acesso
            is_tainted, reason = self._is_tainted(node.value)
            if is_tainted:
                return True, reason
        
        if isinstance(node, ast.BinOp):
            left_tainted, left_reason = self._is_tainted(node.left)
            right_tainted, right_reason = self._is_tainted(node.right)
            if left_tainted:
                return True, left_reason
            if right_tainted:
                return True, right_reason
        
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    is_tainted, reason = self._is_tainted(value.value)
                    if is_tainted:
                        return True, reason
        
        # Propagar taint através de literais Dict, List, Tuple, Set

        if isinstance(node, ast.Dict):
            for key in node.keys:
                if key: 
                    is_tainted, reason = self._is_tainted(key)
                    if is_tainted:
                        return True, reason
            for value in node.values:
                is_tainted, reason = self._is_tainted(value)
                if is_tainted:
                    return True, reason
        
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for elt in node.elts:
                is_tainted, reason = self._is_tainted(elt)
                if is_tainted:
                    return True, reason
        
        

        if isinstance(node, ast.Call):
            # Verificar se a função retorna tainted
            func_name = self._get_full_name(node.func)
            if func_name in self.function_returns and self.function_returns[func_name]:
                return True, f"function '{func_name}' returns tainted data"
            
            # Verificar argumentos
            for arg in node.args:
                is_tainted, reason = self._is_tainted(arg)
                if is_tainted:
                    return True, reason
            
            for kw in node.keywords:
                is_tainted, reason = self._is_tainted(kw.value)
                if is_tainted:
                    return True, reason
        
        return False, ""
    
    def visit_Assign(self, node: ast.Assign):
        """
        Eng:Tracks assignments to propagate taint with detailed info.
        Pt:Rastreia atribuições para propagar taint com informação detalhada.
        """
        is_tainted, reason = self._is_tainted(node.value)
        is_sanitizer, san_name, strength = self._get_sanitizer_strength(node.value)
        
        # Marcar linha se tainted
        if is_tainted:
            if node.lineno not in self.tainted_lines:
                self.tainted_lines[node.lineno] = []
            self.tainted_lines[node.lineno].append(reason)
        
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                
                if is_tainted and not is_sanitizer:
                    # Variável fica tainted
                    is_src, src_name = self._is_source(node.value)
                    self.tainted_vars[var_name] = TaintInfo(
                        var_name=var_name,
                        source=src_name if is_src else reason,
                        line=node.lineno,
                        sanitized=False
                    )
                    self.clean_vars.discard(var_name)
                    
                elif is_tainted and is_sanitizer and strength == "strong":
                    # Sanitizer forte limpa completely
                    self.clean_vars.add(var_name)
                    if var_name in self.tainted_vars:
                        del self.tainted_vars[var_name]
                        
                elif is_tainted and is_sanitizer and strength in ["weak", "context"]:
                    # Sanitizer fraco/contextual: marca mas mantém vigilância
                    self.tainted_vars[var_name] = TaintInfo(
                        var_name=var_name,
                        source=reason,
                        line=node.lineno,
                        sanitized=True,
                        sanitizer_used=san_name
                    )
                    
                elif is_sanitizer and not is_tainted:
                    # Limpar variável existente
                    self.clean_vars.add(var_name)
                    if var_name in self.tainted_vars:
                        del self.tainted_vars[var_name]
            
            # Rastrear containers (dicts, lists)
            elif isinstance(target, ast.Subscript):
                if isinstance(target.value, ast.Name):
                    container_name = target.value.id
                    if is_tainted:
                        self.tainted_containers[container_name] = True
        
        self.generic_visit(node)
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        """
        Eng: Tracks functions that return tainted data (interprocedural)
             AND treats parameters as potential taint sources for in-function analysis.
        Pt: Rastreia funções que retornam dados tainted (interprocedural)
             E trata parâmetros como fontes de taint potenciais para análise intra-função.
        """
        func_name = node.name

        # 1. Salvar o estado de taint do escopo exterior
        original_tainted_vars = self.tainted_vars.copy()
        original_clean_vars = self.clean_vars.copy()
        original_tainted_containers = self.tainted_containers.copy()

        # 2. Tratar parâmetros como tainted *dentro deste escopo*
        for arg in node.args.args:
            var_name = arg.arg
            if var_name in {'self', 'cls'}:  # Ignorar 'self' e 'cls'
                continue

            # Adicionar ao escopo de taint 
            if var_name not in self.tainted_vars:
                self.tainted_vars[var_name] = TaintInfo(
                    var_name=var_name,
                    source="function parameter (assumed tainted)",
                    line=node.lineno,
                    sanitized=False
                )
                self.clean_vars.discard(var_name)

        # Tratar *args e **kwargs como containers tainted
        if node.args.vararg:
            var_name = node.args.vararg.arg
            self.tainted_containers[var_name] = True
        if node.args.kwarg:
            var_name = node.args.kwarg.arg
            self.tainted_containers[var_name] = True
            
        #  Visitar o corpo da função 
        for body_item in node.body:
            self.visit(body_item)

        # Verificar se a função retorna dados tainted
       
        returns_tainted = False
        for child in ast.walk(node):
            if isinstance(child, ast.Return) and child.value:
                is_tainted, _ = self._is_tainted(child.value)
                if is_tainted:
                    returns_tainted = True
                    break
        
        self.function_returns[func_name] = returns_tainted
        self.tainted_vars = original_tainted_vars
        self.clean_vars = original_clean_vars
        self.tainted_containers = original_tainted_containers
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in node.args.defaults:
            self.visit(default)
        for kw_default in node.args.kw_defaults:
            if kw_default:
                self.visit(kw_default)
    
    def visit_Call(self, node: ast.Call):
        """
        Eng:Marks lines where tainted data is used in arguments.
        Pt:Marca linhas onde dados tainted são usados em argumentos.
        """
        for arg in node.args:
            is_tainted, reason = self._is_tainted(arg)
            if is_tainted:
                if node.lineno not in self.tainted_lines:
                    self.tainted_lines[node.lineno] = []
                self.tainted_lines[node.lineno].append(reason)
                break
        
        for kw in node.keywords:
            is_tainted, reason = self._is_tainted(kw.value)
            if is_tainted:
                if node.lineno not in self.tainted_lines:
                    self.tainted_lines[node.lineno] = []
                self.tainted_lines[node.lineno].append(reason)
                break
                
        self.generic_visit(node)
    
    def is_line_tainted(self, line: int) -> bool:
        """
        Eng:Checks if a specific line is tainted
        Pt:Verifica se uma linha específica tem dados tainted
        """
        return line in self.tainted_lines
        
    def get_taint_info(self, line: int) -> List[str]:
        """
        Eng: Returns the reasons why a line is tainted.
        Pt: Retorna as razões pelas quais uma linha está tainted.
        """
        return self.tainted_lines.get(line, [])