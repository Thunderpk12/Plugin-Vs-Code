"""
Eng: Main Security Scanner - Orchestrates all analyzers and AI fixes
Pt: Scanner de Segurança Principal - Orquestra todos os analisadores e correções de IA
"""

import ast
import os
import sys
import json
import argparse
from typing import List, Dict, Any

# Importar modelos e analisadores originais
from models import Vulnerability
from taint_analysis import TaintAnalyzer
from ai_fixer import AIFixer  # Novo módulo para IA

# Analisadores por Categoria
from injection_analyzer import (
    SQLInjectionAnalyzer, CommandInjectionAnalyzer, CodeEvaluationAnalyzer,
    LDAPInjectionAnalyzer, NoSQLInjectionAnalyzer, TemplateInjectionAnalyzer,
    XPathInjectionAnalyzer, XMLInjectionAnalyzer, HeaderInjectionAnalyzer,
    LogInjectionAnalyzer,  
)
from access_control_analyzer import AccessControlAnalyzer
from logging_analyzer import LoggingAnalyzer
from dependency_analyzer import DependencyAnalyzer
from authentication_analyzer import AuthenticationAnalyzer

def analyze_file(file_path: str, 
                 enable_taint_analysis: bool = True, 
                 enable_injection: bool = True,
                 enable_auth: bool = True,
                 enable_logging: bool = True,
                 enable_dependencies: bool = True,
                 enable_access_control: bool = True,
                 silent: bool = False) -> List[Dict[str, Any]]:
    """
    Analisa um ficheiro Python em busca de vulnerabilidades, permitindo
    ligar/desligar categorias específicas conforme a configuração do VS Code.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            code = file.read()
    except Exception as e:
        if not silent: print(f"Error reading file: {e}")
        return []

    try:
        code_ast = ast.parse(code, filename=file_path)
    except SyntaxError as e:
        if not silent: print(f"Syntax error in file (line {e.lineno}): {e.msg}")
        return []

    if not silent: print("Phase 1: Pattern-based detection...")

    ast_visitors = []
    
    # Configuração dinâmica dos analisadores baseada nas flags
    if enable_access_control: ast_visitors.append(AccessControlAnalyzer())
    if enable_auth: ast_visitors.append(AuthenticationAnalyzer())
    if enable_logging: ast_visitors.append(LoggingAnalyzer())
    
    dep_analyzer = DependencyAnalyzer()
    if enable_dependencies: ast_visitors.append(dep_analyzer)

    if enable_injection:
        ast_visitors.extend([
            SQLInjectionAnalyzer(), CommandInjectionAnalyzer(), CodeEvaluationAnalyzer(),
            LDAPInjectionAnalyzer(), NoSQLInjectionAnalyzer(), TemplateInjectionAnalyzer(),
            XPathInjectionAnalyzer(), XMLInjectionAnalyzer(), HeaderInjectionAnalyzer(),
            LogInjectionAnalyzer()
        ])
    
    all_problems: List[Vulnerability] = []

    # Execução dos Visitors na AST
    for analyzer in ast_visitors:
        try:
            analyzer.visit(code_ast)
            all_problems.extend(analyzer.problems)
        except Exception as e:
            if not silent: print(f"Error in {analyzer.__class__.__name__}: {e}")
            
    # Análise de requirements.txt para A06
    if enable_dependencies:
        try:
            file_dir = os.path.dirname(os.path.abspath(file_path))
            req_path = os.path.join(file_dir, "requirements.txt")
            if os.path.exists(req_path):
                dep_analyzer.scan_requirements(req_path)
                all_problems.extend([p for p in dep_analyzer.problems if p.function == 'requirements.txt'])
        except: pass

    # Phase 2: Taint Analysis Refinement (Apenas para A03)
    if enable_taint_analysis and enable_injection:
        if not silent: print("Phase 2: Taint analysis refinement (A03)...")
        taint_analyzer = TaintAnalyzer()
        try:
            taint_analyzer.visit(code_ast)
            refined_problems = []
            for vuln in all_problems:
                if vuln.category == "A03":
                    is_tainted = taint_analyzer.is_line_tainted(vuln.line)
                    is_taint_dependent = any(x in vuln.pattern for x in ["variable", "f-string", "concatenation", "format"])
                    
                    if is_tainted:
                        vuln.confidence = "HIGH"
                        vuln.tainted = True
                        refined_problems.append(vuln)
                    elif not is_taint_dependent:
                        refined_problems.append(vuln)
                    else:
                        vuln.confidence = "LOW"
                        vuln.description += " (Taint not confirmed)"
                        refined_problems.append(vuln)
                else:
                    refined_problems.append(vuln)
            return [v.to_dict() for v in refined_problems]
        except: pass
    
    return [v.to_dict() for v in all_problems]

# --- CLI e Argumentos ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Python Vulnerability Scanner')
    parser.add_argument('file', nargs='?', help='File to analyze')
    parser.add_argument('--json-only', action='store_true')
    parser.add_argument('--skip-access-control', action='store_true')
    parser.add_argument('--skip-injection', action='store_true')
    parser.add_argument('--skip-auth', action='store_true')
    parser.add_argument('--skip-logging', action='store_true')
    parser.add_argument('--skip-dependencies', action='store_true')
    parser.add_argument('--no-taint', action='store_true')

    # Novas flags para IA
    parser.add_argument('--suggest-fix', help='Line of code to fix')
    parser.add_argument('--vuln-type', help='Description of the error')

    args = parser.parse_args()

    # Fluxo Especial para Correção por IA
    if args.suggest_fix:
        fixer = AIFixer()
        print(fixer.get_fix(args.suggest_fix, args.vuln_type or "Security Vulnerability"))
        sys.exit(0)

    # Fluxo de Análise Normal
    if args.file:
        found_problems = analyze_file(
            args.file, 
            enable_taint_analysis=not args.no_taint,
            enable_injection=not args.skip_injection,
            enable_auth=not args.skip_auth,
            enable_logging=not args.skip_logging,
            enable_dependencies=not args.skip_dependencies,
            enable_access_control=not args.skip_access_control,
            silent=args.json_only
        )
        print(json.dumps(found_problems)) if args.json_only else print(found_problems)