"""
Pt: A06:2021 - Vulnerable and Outdated Components
Eng: A06:2021 - Vulnerable and Outdated Components

Este analisador deteta:
- Imports de bibliotecas conhecidas como vulneráveis
- Uso de funções/métodos deprecated
- Dependências sem pinning de versão
- Bibliotecas com versões conhecidas vulneráveis
"""

import ast
import os
from typing import List, Dict, Set, Optional
from models import Vulnerability

class DependencyAnalyzer(ast.NodeVisitor):
    """
    Pt: Analisa dependências e componentes vulneráveis
    Eng: Analyzes dependencies and vulnerable components
    """
    
    # Bibliotecas conhecidas com vulnerabilidades críticas em versões antigas ou por natureza
    VULNERABLE_LIBRARIES = {
        'pickle': {
            'severity': 'HIGH',
            'reason': 'Unsafe deserialization - use safer alternatives (json)',
        },
        'cPickle': {
            'severity': 'HIGH',
            'reason': 'Unsafe deserialization - use safer alternatives (json)',
        },
        'yaml': {
            'severity': 'HIGH', 
            'reason': 'Unsafe YAML loading - use yaml.safe_load()',
            'safe_functions': {'safe_load', 'safe_load_all'}
        },
        'urllib2': {
            'severity': 'MEDIUM',
            'reason': 'Deprecated - use urllib3 or requests',
        },
        'md5': {
            'severity': 'MEDIUM',
            'reason': 'MD5 is cryptographically broken - use SHA256+',
        },
        'sha1': {
            'severity': 'MEDIUM',
            'reason': 'SHA1 is weak - use SHA256+',
        },
        'xmlrpc': {
            'severity': 'HIGH',
            'reason': 'XML-RPC is often vulnerable to brute force and DoS',
        },
        'telnetlib': {
            'severity': 'HIGH',
            'reason': 'Telnet is insecure (clear text). Use SSH (paramiko).',
        }
    }
    
    # Funções deprecated ou inseguras
    DEPRECATED_FUNCTIONS = {
        'os.popen': 'Use subprocess.run() instead',
        'os.tempnam': 'Use tempfile module instead',
        'os.tmpnam': 'Use tempfile module instead',
        'random.random': 'Use secrets module for cryptographic purposes',
        'eval': 'Avoid eval() - use ast.literal_eval() or safer alternatives',
        'exec': 'Avoid exec() - use safer alternatives',
    }
    
    # Funções inseguras do YAML (Nomes exatos)
    UNSAFE_YAML_FUNCTIONS = {'load', 'load_all', 'FullLoader', 'UnsafeLoader'}
    
    def __init__(self):
        self.problems: List[Vulnerability] = []
        self.imported_modules: Set[str] = set()
        
    def _get_full_name(self, node: ast.AST) -> str:
        """Helper para obter nome completo (ex: yaml.load)"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            parent = self._get_full_name(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""
    
    def visit_Import(self, node: ast.Import):
        """
        Pt: Deteta imports de bibliotecas vulneráveis
        """
        for alias in node.names:
            module_name = alias.name.split('.')[0]  # Pegar root module
            self.imported_modules.add(module_name)
            
            if module_name in self.VULNERABLE_LIBRARIES:
                vuln_info = self.VULNERABLE_LIBRARIES[module_name]
                self.problems.append(Vulnerability(
                    line=node.lineno,
                    column=node.col_offset,
                    type='Vulnerable Library Import',
                    function='import statement',
                    pattern=f"import {module_name}",
                    description=f"Library '{module_name}' has known issues: {vuln_info['reason']}",
                    severity=vuln_info['severity'],
                    confidence="HIGH",
                    category="A06"
                ))
        
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom):
        """
        Pt: Deteta imports específicos de módulos vulneráveis
        """
        if node.module:
            module_name = node.module.split('.')[0]
            self.imported_modules.add(module_name)
            
            if module_name in self.VULNERABLE_LIBRARIES:
                vuln_info = self.VULNERABLE_LIBRARIES[module_name]
                
                # Caso especial: yaml
                if module_name == 'yaml':
                    imported_names = {alias.name for alias in node.names}
                    safe_funcs = vuln_info.get('safe_functions', set())
                    
                    # Se importar APENAS funções seguras, não reportar
                    if imported_names.issubset(safe_funcs):
                        self.generic_visit(node)
                        return
                
                self.problems.append(Vulnerability(
                    line=node.lineno,
                    column=node.col_offset,
                    type='Vulnerable Library Import',
                    function='import statement',
                    pattern=f"from {module_name} import ...",
                    description=f"Importing from '{module_name}': {vuln_info['reason']}",
                    severity=vuln_info['severity'],
                    confidence="HIGH",
                    category="A06"
                ))
        
        self.generic_visit(node)
    
    def visit_Call(self, node: ast.Call):
        """
        Pt: Deteta uso de funções deprecated ou inseguras
        """
        func_name = self._get_full_name(node.func)
        
        if func_name in self.DEPRECATED_FUNCTIONS:
            self.problems.append(Vulnerability(
                line=node.lineno,
                column=node.col_offset,
                type='Deprecated/Unsafe Function',
                function=func_name,
                pattern=f"use of {func_name}()",
                description=f"Function '{func_name}' is deprecated or unsafe. {self.DEPRECATED_FUNCTIONS[func_name]}",
                severity="MEDIUM",
                confidence="HIGH",
                category="A06"
            ))
        
        # Caso especial: yaml.load() inseguro
        if 'yaml' in self.imported_modules:
            # CORREÇÃO: Verificar o nome exato do método, não apenas se contém a string "load"
            # Isto evita falsos positivos com 'json.loads', 'yaml.safe_load', 'pickle.loads'
            
            parts = func_name.split('.')
            method_name = parts[-1] # Apanha 'load', 'safe_load', 'loads'
            module_prefix = parts[0] if len(parts) > 1 else None

            # Verifica se o método é inseguro E (se tiver prefixo) garante que não é json/pickle
            if method_name in self.UNSAFE_YAML_FUNCTIONS:
                # Se for json.load ou pickle.load, ignoramos
                if module_prefix and module_prefix in {'json', 'pickle', 'cPickle'}:
                    pass
                else:
                    # Verificar se usa Loader seguro nos argumentos
                    uses_safe_loader = False
                    for kw in node.keywords:
                        if kw.arg == 'Loader':
                            loader_name = self._get_full_name(kw.value)
                            if 'SafeLoader' in loader_name or 'BaseLoader' in loader_name:
                                uses_safe_loader = True
                    
                    if not uses_safe_loader:
                        self.problems.append(Vulnerability(
                            line=node.lineno,
                            column=node.col_offset,
                            type='Unsafe YAML Loading',
                            function=func_name,
                            pattern='yaml.load() without SafeLoader',
                            description="Using yaml.load() without SafeLoader enables arbitrary code execution. Use yaml.safe_load() instead.",
                            severity="HIGH",
                            confidence="HIGH",
                            category="A06"
                        ))
        
        # Caso especial: pickle
        if 'pickle' in self.imported_modules or 'cPickle' in self.imported_modules:
            # Aqui também verificamos strings específicas
            if 'pickle.load' in func_name or 'pickle.loads' in func_name:
                self.problems.append(Vulnerability(
                    line=node.lineno,
                    column=node.col_offset,
                    type='Unsafe Deserialization',
                    function=func_name,
                    pattern='pickle.load()',
                    description="Pickle deserialization of untrusted data can lead to arbitrary code execution.",
                    severity="HIGH",
                    confidence="MEDIUM",
                    category="A06"
                ))
        
        # Caso especial: hashlib com algoritmos fracos
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in {'md5', 'sha1'}:
                self.problems.append(Vulnerability(
                    line=node.lineno,
                    column=node.col_offset,
                    type='Weak Cryptographic Hash',
                    function=func_name,
                    pattern=f'use of {node.func.attr}',
                    description=f"{node.func.attr.upper()} is cryptographically weak. Use SHA256 or stronger.",
                    severity="MEDIUM",
                    confidence="HIGH",
                    category="A06"
                ))
        
        self.generic_visit(node)

    def scan_requirements(self, requirements_path: str):
        """
        Pt: Analisa ficheiro requirements.txt para versões pinned
        """
        if not os.path.exists(requirements_path):
            return

        try:
            with open(requirements_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    
                    # Ignorar comentários e linhas vazias
                    if not line or line.startswith('#'):
                        continue
                    
                    package_name = line.split('[')[0].split('==')[0].split('>=')[0].strip()

                    # Vulnerabilidade 1: Falta de Version Pinning
                    if '==' not in line:
                        self.problems.append(Vulnerability(
                            line=line_num,
                            column=0,
                            type='Unpinned Dependency',
                            function='requirements.txt',
                            pattern=package_name,
                            description=f"Package '{package_name}' is not pinned to a specific version (missing '=='). This can lead to supply chain attacks.",
                            severity='LOW',
                            confidence="HIGH",
                            category="A06"
                        ))
                    
                    # Vulnerabilidade 2: Uso de >= (Permite updates maliciosos futuros)
                    if '>=' in line:
                        self.problems.append(Vulnerability(
                            line=line_num,
                            column=0,
                            type='Loose Dependency Version',
                            function='requirements.txt',
                            pattern='>= operator',
                            description=f"Package '{package_name}' uses '>=' which allows automatic updates to potentially vulnerable versions.",
                            severity='LOW',
                            confidence="HIGH",
                            category="A06"
                        ))

        except Exception as e:
            print(f"Error reading requirements.txt: {e}")