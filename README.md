Plugin para Visual Studio Code que deteta vulnerabilidades de segurança em código Python.
🎯 Objetivo
Análise estática de segurança focando em OWASP Top 10 (A03, A06, A09).
🚧 Status: Em Desenvolvimento
Semana 1 - Setup inicial e pesquisa
Semana 2 -  Pesquisa e estudo sobre injections
Semana 3 -  Protótipo de análise de injections
🚧 Notas de desenvolvimento:
Ficheiro scanner.py - O código le um arquivo python e transforma o em AST, de seguida percorre a arvore e procura padrões perigosos.
SQL Injection
Funções monitorizadas: execute, executemany, query, raw
Padrões detectados:
F-strings com variáveis: f"SELECT * FROM users WHERE id = {user_id}"
Concatenação de strings: "SELECT * FROM users WHERE id = " + user_id
Método .format(): "SELECT * FROM users WHERE id = {}".format(user_id)
Formatação com %: "SELECT * FROM users WHERE id = %s" % user_id
Variáveis não validadas passadas diretamente
Acesso a subscripts (dicionários/listas)
Acesso a atributos de objetos
Command Injection
Funções monitorizadas: system, run, Popen, call, check_output, check_call, popen
Padrões detectados: Mesmos padrões da SQL Injection aplicados a comandos de sistema
Code Injection
Funções monitorizadas: eval, exec, compile, import
Padrões detectados: Mesmos padrões aplicados a execução dinâmica de código
🚫 Vulnerabilidades Não Detectadas
Injection (ideias para desenvolvimento futuro)
LDAP Injection
NoSQL Injection
Template Injection
XML/XXE Injection
XPath Injection
Header Injection (HTTP)
Log Injection