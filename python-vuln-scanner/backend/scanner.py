"""
Eng: Main Security Scanner - Orchestrates all analyzers
Pt: Scanner de Segurança Principal - Orquestra todos os analisadores
"""

import ast
import os
import sys
import json
import argparse
from typing import List, Dict, Any

# Importar modelos e analisadores
from models import Vulnerability
from taint_analysis import TaintAnalyzer

# A03 - Injection Analyzers
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

# A01 - Access Control Analyzer
from access_control_analyzer import AccessControlAnalyzer

# A09 - Logging Analyzer
from logging_analyzer import LoggingAnalyzer

# A06 - Dependency Analyzer
from dependency_analyzer import DependencyAnalyzer

# A07 - Authentication Analyzer (NOVO)
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
    ligar/desligar categorias específicas.
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
    
    if not silent:
        print("Phase 1: Pattern-based detection...")
    
   
    ast_visitors = []
    
    if enable_access_control:
        if not silent: print("   [+] Access Control Analyzer (A01) enabled")
        ast_visitors.append(AccessControlAnalyzer())

    # [A03] Injection
    if enable_injection:
        if not silent: print("   [+] Injection Analyzers (A03) enabled")
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
        ast_visitors.extend(injection_analyzers)

    # [A07] Authentication (NOVO)
    if enable_auth:
        if not silent: print("   [+] Authentication Analyzers (A07) enabled")
        ast_visitors.append(AuthenticationAnalyzer())

    # [A09] Logging
    if enable_logging:
        if not silent: print("   [+] Logging Analyzers (A09) enabled")
        ast_visitors.append(LoggingAnalyzer())

    # [A06] Dependencies (Código Fonte)
    dep_analyzer = DependencyAnalyzer()
    if enable_dependencies:
        if not silent: print("   [+] Dependency Analyzer (A06) enabled")
        ast_visitors.append(dep_analyzer)
    
    all_problems: List[Vulnerability] = []

    # 4. Executar Visitors na AST
    for analyzer in ast_visitors:
        try:
            analyzer.visit(code_ast)
            all_problems.extend(analyzer.problems)
        except Exception as e:
            if not silent: print(f"Error running analyzer {analyzer.__class__.__name__}: {e}")
            
    # 5. Executar análise de requirements.txt (A06 Extra)
    # Só corre se enable_dependencies for True e encontrar o ficheiro
    if enable_dependencies:
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
    
    # 6. Taint Analysis (Refinamento)
    # Só executamos se estiver ativado E se a categoria Injection estiver ativa
    # (pois o taint refinement atual foca-se em fluxos de injeção)
    if enable_taint_analysis and enable_injection:
        if not silent: print("Phase 2: Taint analysis refinement (A03)...")
        taint_analyzer = TaintAnalyzer()
        try:
            taint_analyzer.visit(code_ast)
            
            refined_problems = []
            tainted_count = 0
            low_conf_count = 0
            pattern_conf_count = 0
            
            for vuln in all_problems:
                # Apenas refinar injeções (A03) com taint
                if vuln.category == "A03":
                    is_tainted = taint_analyzer.is_line_tainted(vuln.line)
                    
                    # Padrões que dependem de variáveis
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
                        # Se é um literal inseguro (ex: eval("print(x)")), mantém
                        refined_problems.append(vuln)
                        pattern_conf_count += 1
                    else:
                        # Se depende de variável mas não está 'tainted', baixa confiança
                        vuln.confidence = "LOW"
                        vuln.description += " (Taint not confirmed - review manually)"
                        refined_problems.append(vuln)
                        low_conf_count += 1
                else:
                    # A06, A07, A09 e outros: passam sem taint analysis
                    refined_problems.append(vuln)
            
            if not silent:
                print(f"   {tainted_count} A03 confirmed with taint analysis")
                print(f"   {pattern_conf_count} A03 confirmed by static pattern")
                print(f"   {low_conf_count} A03 marked as low confidence")
            
            return [v.to_dict() for v in refined_problems]
            
        except Exception as e:
            if not silent: print(f"Error during taint analysis: {e}")
            return [v.to_dict() for v in all_problems]
    
    return [v.to_dict() for v in all_problems]


# ===================== RESULTS PRESENTATION =====================

def show_results(problems: List[Dict[str, Any]], verbose: bool = True, show_low_confidence: bool = True):
    """Exibe os resultados organizados por categoria OWASP"""
    if not problems:
        print("No security problems found")
        return
    
    if not show_low_confidence:
        problems = [p for p in problems if p['confidence'] != 'LOW']
    
    if not problems:
        print("No high/medium-confidence security problems found")
        return
    
    # Agrupar por categoria
    by_category: Dict[str, List[Dict[str, Any]]] = {}
    for p in problems:
        cat = p.get('category', 'UNKNOWN')
        by_category.setdefault(cat, []).append(p)
    
    print(f"\n{'='*70}")
    print(f"Found {len(problems)} potential vulnerabilities")
    for cat, vulns in sorted(by_category.items()):
        print(f"   {cat}: {len(vulns)} issues")
    print(f"{'='*70}")
    
    # Mostrar por categoria
    for category in sorted(by_category.keys()):
        cat_problems = by_category[category]
        
        # Ordenar problemas dentro da categoria
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
    """Exporta resultados para JSON"""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(problems, f, indent=2, ensure_ascii=False)
        print(f"\nResults exported to: {output_file}")
    except Exception as e:
        print(f"Error exporting JSON: {e}")


# ===================== MAIN EXECUTION =====================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Python Vulnerability Scanner')
    
    
    parser.add_argument('file', help='File to analyze')
    

    parser.add_argument('--json-only', action='store_true', help='Output only JSON for VS Code integration')
    
    parser.add_argument('--skip-access-control', action='store_true', help='Disable A01 Access Control checks')
    parser.add_argument('--skip-injection', action='store_true', help='Disable A03 Injection checks')
    parser.add_argument('--skip-auth', action='store_true', help='Disable A07 Auth checks')
    parser.add_argument('--skip-logging', action='store_true', help='Disable A09 Logging checks')
    parser.add_argument('--skip-dependencies', action='store_true', help='Disable A06 Dependency checks')
    parser.add_argument('--no-taint', action='store_true', help='Disable Deep Taint Analysis')

    args = parser.parse_args()
    
    
    if not args.json_only:
        print(f"\nAnalyzing file: {args.file}")
        print(f"Configuration:")
        print(f"  - Access Control (A01): {'DISABLED' if args.skip_access_control else 'ENABLED'}")
        print(f"  - Injection (A03): {'DISABLED' if args.skip_injection else 'ENABLED'}")
        print(f"  - Auth (A07):      {'DISABLED' if args.skip_auth else 'ENABLED'}")
        print(f"  - Logging (A09):   {'DISABLED' if args.skip_logging else 'ENABLED'}")
        print(f"  - Deps (A06):      {'DISABLED' if args.skip_dependencies else 'ENABLED'}")
        print(f"  - Taint Analysis:  {'DISABLED' if args.no_taint else 'ENABLED'}")
        print()

   
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
    
    if args.json_only:
       
        print(json.dumps(found_problems))
    else:
        
        show_results(found_problems, verbose=True, show_low_confidence=True)