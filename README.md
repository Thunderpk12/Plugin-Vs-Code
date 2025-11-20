🐍 Python Vulnerability Scanner (Protótipo VS Code)

Plugin para Visual Studio Code (em desenvolvimento) que deteta vulnerabilidades de segurança em código Python.

🎯 Objetivo

Análise estática de segurança focando em OWASP Top 10 (A03, A06, A09).

✨ Funcionalidades Principais

Este scanner vai além da simples correspondência de texto:
Análise de AST: O código é transformado numa Árvore de Sintaxe Abstrata (AST), permitindo uma análise profunda e precisa da estrutura do código.
Análise de Taint (Mancha): O scanner implementa um motor de Taint Analysis para rastrear o fluxo de dados não confiáveis (ex: request.args.get) até funções perigosas (ex: cursor.execute).
Deteção Contextual: O motor consegue identificar "Sanitizers" (ex: shlex.quote) que "limpam" os dados, reduzindo falsos positivos.
Classificação de Confiança: As vulnerabilidades são classificadas como:
HIGH Confidence: Confirmadas pelo Taint Analysis (ex: dados do utilizador chegam a uma função perigosa).
LOW Confidence: Padrões perigosos encontrados, mas o Taint Analysis não confirmou o fluxo (requer revisão manual).

🛡️ Vulnerabilidades Detetadas

Injection_analyzer:
-SQL Injection: cursor.execute(f"...")
-Command Injection: os.system(...), subprocess.run(...)
-Code Injection: eval(), exec()
-LDAP Injection: ldap.search_s(f"...")
-NoSQL Injection: db.users.find({"$where": "..."})
-Template Injection (SSTI): Template(f"...")
-XML / XXE Injection: ET.fromstring(...)
-XPath Injection: root.xpath(f"...")
-Header Injection (CRLF): response.headers['...'] = ...
-Log Injection: logging.error(f"...")

Logging_analyzer:
-Missing Security Logging
-Sensitive Data in Logs
-Inappropriate Log Level
-Unlogged Exceptions

⚙️ Como Funciona (Notas de Desenvolvimento)
O núcleo do scanner (scanner.py) opera num processo de duas fases:

Fase 1: Deteção de Padrões (BaseAnalyzers)
O código Python do utilizador é lido e transformado numa AST (ast.parse).
Uma série de "Visitors" (ex: SQLInjectionAnalyzer, CommandInjectionAnalyzer) percorre a árvore.
Estes visitors procuram por Sinks (funções de risco, ex: cursor.execute) que estão a ser chamadas com Padrões Perigosos (ex: f-strings, variáveis diretas).
É gerada uma lista de "potenciais problemas".
Fase 2: Refinamento com Taint Analysis (TaintAnalyzer)
Um segundo visitor, o TaintAnalyzer, percorre a árvore novamente com um objetivo diferente: rastrear o fluxo de dados.
Sources (Fontes): Ele identifica todas as fontes de dados não confiáveis (ex: request.args.get, input()) e "mancha" (taints) as variáveis que os recebem.
Sanitizers (Higienizadores): Ele identifica funções que "limpam" os dados (ex: shlex.quote, int()). Se uma variável "manchada" passa por um sanitizer, ela é marcada como "limpa".

🚀 Estado do Projeto e Cronograma

Semana 1 - Setup inicial e pesquisa sobre AST.
Semana 2 - Pesquisa e estudo sobre Injections .
Semana 3 - Protótipo de análise de padrões (BaseAnalyzers) para SQLi e Command-i.
Semana 4 - Implementação do motor de Taint Analysis (TaintAnalyzer) e expansão para todas as 10 classes de injeção (A03).
Semana 5 -  Refinamento do Taint Analysis (adição de Sanitizers) e lógica de confiança. Correção de falsos positivos e falsos negativos.
Semana 6 - Estudo sobre Security Logging and Monitoring Failues, prótito.
Semana 7 - refinamento do logging_analyzer 
Semana 8 - (Semana atual) -> dependency_analyzer



