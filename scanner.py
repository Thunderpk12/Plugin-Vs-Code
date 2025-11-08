"""
Eng:Main Security Scanner - Orchestrates all analyzers
Pt:Scanner de Segurança Principal - Orquestra todos os analisadores
"""

import ast
from typing import List, Dict, Any
import json
import sys


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
from logging_analyzer import EnhancedLoggingAnalyzer

def analyze_file(file_path: str, enable_taint_analysis: bool = True) -> List[Dict[str, Any]]:
    """
    Analisa um ficheiro Python em busca de vulnerabilidades de segurança
    em múltiplas categorias OWASP.
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
        LogInjectionAnalyzer(), # A03
    ]
    
    # A09: Analisadores de Falhas de Logging
    logging_analyzers = [
       EnhancedLoggingAnalyzer(),
    ]

    all_analyzers = injection_analyzers + logging_analyzers
    all_problems: List[Vulnerability] = []

    for analyzer in all_analyzers:
        try:
            analyzer.visit(code_ast)
            all_problems.extend(analyzer.problems)
        except Exception as e:
            print(f"Error running analyzer {analyzer.__class__.__name__}: {e}")
    
    print(f"   Found {len(all_problems)} potential issues")
    
    # Taint analysis (refinamento apenas para A03 - Injection)
    if enable_taint_analysis:
        print("Phase 2: Taint analysis refinement (A03 only)...")
        taint_analyzer = TaintAnalyzer()
        taint_analyzer.visit(code_ast)
        
        refined_problems = []
        tainted_count = 0
        low_conf_count = 0
        pattern_conf_count = 0
        
        for vuln in all_problems:
            # Apenas refinar injeções com taint
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
                    # Ex: XXE estático (resolve_entities=True)
                    refined_problems.append(vuln)
                    pattern_conf_count += 1
                else:
                    vuln.confidence = "LOW"
                    vuln.description += " (Taint not confirmed - review manually)"
                    refined_problems.append(vuln)
                    low_conf_count += 1
            else:
                # A09 e outros: passam sem taint analysis
                refined_problems.append(vuln)
        
        print(f"   {tainted_count} A03 confirmed with taint analysis")
        print(f"   {pattern_conf_count} A03 confirmed by static pattern")
        print(f"   {low_conf_count} A03 marked as low confidence")
        
        return [v.to_dict() for v in refined_problems]
    
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
    print(f"Found {len(problems)} potential vulnerabilities (showing { 'all' if show_low_confidence else 'medium/high confidence' })")
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
                print(f"    Function:    {problem['function']}()")
                print(f"    Pattern:     {problem['pattern']}")
                print(f"    Description: {problem['description']}")
                if problem.get('tainted'):
                    print(f"    Confirmed by taint analysis")
                print()
        else:
            for problem in cat_problems:
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
    
    file_to_analyze = sys.argv[1] if len(sys.argv) > 1 else "vulneravel.py"
    enable_taint = True
    export_file = None 
    hide_low = False
    brief_output = False
    
    print(f"\nAnalyzing file: {file_to_analyze}")
    print(f"   Taint analysis: {'enabled' if enable_taint else 'disabled'}")
    print()
    
    found_problems = analyze_file(file_to_analyze, enable_taint_analysis=enable_taint)
    
    show_results(found_problems, verbose=not brief_output, show_low_confidence=not hide_low)
    
    if export_file:
        export_json(found_problems, export_file)