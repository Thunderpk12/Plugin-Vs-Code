"""
Eng: Shared data models for all security analyzers
PT: Modelos de dados partilhados para todos os analisadores de segurança
"""
from dataclasses import dataclass, field
from typing import Any, Dict

@dataclass
class Vulnerability:
    """
    Pt:Estrutura de vulnerabilidade universal para todos os tipos de analisadores.
    Eng:Universal vulnerability structure for all analyzer types.
    """
    line: int
    column: int
    type: str  # Ex: "SQL Injection", "Security Logging Failure"
    function: str
    pattern: str
    description: str
    severity: str = "MEDIUM"  # HIGH, MEDIUM, LOW
    confidence: str = "MEDIUM"  # HIGH, MEDIUM, LOW
    tainted: bool = False  # Para injection analyzers
    category: str = "A03"  # A03 (Injection), A09 (Logging), etc.
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Eng: Converts the vulnerability to a dictionary for serialization
        Pt: Converte a vulnerabilidade num dicionário para serialização.
        """
        return {
            'line': self.line,
            'column': self.column,
            'type': self.type,
            'function': self.function,
            'pattern': self.pattern,
            'description': self.description,
            'severity': self.severity,
            'confidence': self.confidence,
            'tainted': self.tainted,
            'category': self.category
        }