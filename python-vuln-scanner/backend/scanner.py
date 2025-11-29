"""
Eng:Main Security Scanner - Orchestrates all analyzers
Pt:Scanner de Segurança Principal - Orquestra todos os analisadores
"""

import ast
import os
from typing import List, Dict, Any
import json
import sys
import argparse # Importante para ler os argumentos

from models import Vulnerability
from taint_analysis import TaintAnalyzer
from injection_analyzer import (
    SQLInjectionAnalyzer,
    CommandInjectionAnalyzer,
    CodeEvaluationAnalyzer,
    LDAPInjectionAnalyzer,
    NoSQLInjectionAnalyzer,
    TemplateInjectionAnalyzer,
    XPathInjectionAnalyzer,
    XMLInjectionAnalyzer,
    HeaderInjectionAnalyzer,
    LogInjectionAnalyzer,  
)
from logging_analyzer import LoggingAnalyzer
from dependency_analyzer import DependencyAnalyzer

# Adicionei o parametro 'silent'
def analyze_file(file_path: str, enable_taint_analysis: bool = True, silent: bool = False) -> List[Dict[str, Any]]:
    """
    Analisa um ficheiro Python em busca de vulnerabilidades.
    Se silent=True, não faz prints para a consola (apenas retorna a lista).
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            code = file.read()
    except FileNotFoundError:
        if not silent: print(f"Error: File '{file_path}' not found.")
        return []
    except Exception as e:
        if not silent: print(f"Error reading file: {e}")
        return []

    try:
        code_ast = ast.parse(code, filename=file_path)
    except SyntaxError as e:
        if not silent: print(f"Syntax error in file (line {e.lineno}): {e.msg}")
        return []
    
    # Só imprime se NÃO estiver em modo silencioso
    if not silent:
        print("Phase 1: Pattern-based detection...")
    
    # A03: Analisadores de Injeção
    injection_analyzers = [
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
    
    # A09: Analisadores de Falhas de Logging
    logging_analyzers = [
       LoggingAnalyzer(),
    ]

    # A06: Componentes Vulneráveis
    dep_analyzer = DependencyAnalyzer()
    
    # Lista base de visitantes AST
    ast_visitors = injection_analyzers + logging_analyzers + [dep_analyzer]
    
    all_problems: List[Vulnerability] = []

    # 1. Executar Visitors na AST
    for analyzer in ast_visitors:
        try:
            analyzer.visit(code_ast)
            all_problems.extend(analyzer.problems)
        except Exception as e:
            if not silent: print(f"Error running analyzer {analyzer.__class__.__name__}: {e}")
            
    # 2. Executar análise de requirements.txt
    try:
        file_dir = os.path.dirname(os.path.abspath(file_path))
        req_path = os.path.join(file_dir, "requirements.txt")
        if os.path.exists(req_path):
            if not silent: print(f"   [A06] Analyzing dependencies in: {req_path}")
            dep_analyzer.scan_requirements(req_path)
         
            for p in dep_analyzer.problems:
                if p.function == 'requirements.txt':
                    all_problems.append(p)
    except Exception as e:
        if not silent: print(f"Error checking requirements: {e}")

    if not silent:
        print(f"   Found {len(all_problems)} potential issues")
    
    # Taint analysis
    if enable_taint_analysis:
        if not silent: print("Phase 2: Taint analysis refinement (A03 only)...")
        taint_analyzer = TaintAnalyzer()
        taint_analyzer.visit(code_ast)
        
        refined_problems = []
        tainted_count = 0
        low_conf_count = 0
        pattern_conf_count = 0
        
        for vuln in all_problems:
            if vuln.category == "A03":
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
                    refined_problems.append(vuln)
                    pattern_conf_count += 1
                else:
                    vuln.confidence = "LOW"
                    vuln.description += " (Taint not confirmed - review manually)"
                    refined_problems.append(vuln)
                    low_conf_count += 1
            else:
                refined_problems.append(vuln)
        
        if not silent:
            print(f"   {tainted_count} A03 confirmed with taint analysis")
            print(f"   {pattern_conf_count} A03 confirmed by static pattern")
            print(f"   {low_conf_count} A03 marked as low confidence")
        
        return [v.to_dict() for v in refined_problems]
    
    return [v.to_dict() for v in all_problems]


# ===================== RESULTS PRESENTATION =====================

def show_results(problems: List[Dict[str, Any]], verbose: bool = True, show_low_confidence: bool = True):
    if not problems:
        print("No security problems found")
        return
    
    if not show_low_confidence:
        problems = [p for p in problems if p['confidence'] != 'LOW']
    
    if not problems:
        print("No high/medium-confidence security problems found")
        return
    
    by_category: Dict[str, List[Dict[str, Any]]] = {}
    for p in problems:
        cat = p.get('category', 'UNKNOWN')
        by_category.setdefault(cat, []).append(p)
    
    print(f"\n{'='*70}")
    print(f"Found {len(problems)} potential vulnerabilities")
    for cat, vulns in sorted(by_category.items()):
        print(f"   {cat}: {len(vulns)} issues")
    print(f"{'='*70}")
    
    for category in sorted(by_category.keys()):
        cat_problems = by_category[category]
        cat_problems.sort(key=lambda p: (
            {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}.get(p['severity'], 9),
            {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}.get(p['confidence'], 9),
            p['line'],
            p['column']
        ))
        
        print(f"\n--- {category} ---")
        if verbose:
            for i, problem in enumerate(cat_problems, 1):
                severity_tag = problem['severity']
                confidence_tag = problem['confidence']
                print(f"Problem #{i} [{severity_tag}] [{confidence_tag}]")
                print(f"    Location:    Line {problem['line']}, Column {problem['column']}")
                print(f"    Type:        {problem['type']}")
                print(f"    Function:    {problem['function']}")
                print(f"    Pattern:     {problem['pattern']}")
                print(f"    Description: {problem['description']}")
                if problem.get('tainted'):
                    print(f"    Confirmed by taint analysis")
                print()
        else:
            for problem in cat_problems:
                print(f"L{problem['line']}: [{problem['severity']}/{problem['confidence']}] {problem['type']} in {problem['function']}")

def export_json(problems: List[Dict[str, Any]], output_file: str = "analysis_results.json"):
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(problems, f, indent=2, ensure_ascii=False)
        print(f"\nResults exported to: {output_file}")
    except Exception as e:
        print(f"Error exporting JSON: {e}")

# ==========================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Python Vulnerability Scanner')
    parser.add_argument('file', help='File to analyze')
    parser.add_argument('--json-only', action='store_true', help='Output only JSON for VS Code')
    
    args = parser.parse_args()
    
    # Se NÃO for json-only, imprime o cabeçalho
    if not args.json_only:
        print(f"\nAnalyzing file: {args.file}")

    # Passamos o argumento silent=args.json_only para a função principal
    found_problems = analyze_file(args.file, enable_taint_analysis=True, silent=args.json_only)
    
    if args.json_only:
        # AQUI É O SEGREDO: Só imprime o JSON, nada mais
        print(json.dumps(found_problems))
    else:
        # Modo humano
        show_results(found_problems, verbose=True, show_low_confidence=True)