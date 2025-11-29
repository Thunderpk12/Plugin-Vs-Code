import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

// Define o formato do JSON que vem do Python
interface Vulnerability {
    line: number;
    column: number;
    type: string;
    function: string;
    pattern: string;
    description: string;
    severity: 'HIGH' | 'MEDIUM' | 'LOW';
    confidence: string;
    category: string;
}

let diagnosticCollection: vscode.DiagnosticCollection;
let outputChannel: vscode.OutputChannel;

export function activate(context: vscode.ExtensionContext) {
    // 1. Criar canal de Output para ver logs
    outputChannel = vscode.window.createOutputChannel("Python Vuln Scanner");
    outputChannel.appendLine("Extensão a iniciar...");
    
    // 2. Mensagem visual de confirmação (Prova de Vida)
    vscode.window.showInformationMessage("🚀 O Scanner de Segurança está ATIVO!"); 

    // 3. Criar a coleção de diagnósticos
    diagnosticCollection = vscode.languages.createDiagnosticCollection('python-vuln-scanner');
    context.subscriptions.push(diagnosticCollection);

    // 4. Registar eventos
    // Analisar quando salva
    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(document => {
            if (document.languageId === 'python') {
                runScanner(document, context);
            }
        })
    );

    // Analisar quando muda de aba
    context.subscriptions.push(
        vscode.window.onDidChangeActiveTextEditor(editor => {
            if (editor && editor.document.languageId === 'python') {
                runScanner(editor.document, context);
            }
        })
    );

    outputChannel.appendLine("Extensão carregada com sucesso e à espera de ficheiros Python.");
}

function runScanner(document: vscode.TextDocument, context: vscode.ExtensionContext) {
    // 1. Caminho absoluto para o script Python dentro da pasta da extensão
    const scriptPath = path.join(context.extensionPath, 'backend', 'scanner.py');
    const filePath = document.fileName;

    // Debug: Verificar caminhos no Output
    outputChannel.appendLine(`--- A analisar: ${filePath} ---`);

    if (!fs.existsSync(scriptPath)) {
        vscode.window.showErrorMessage(`ERRO CRÍTICO: Scanner não encontrado em: ${scriptPath}`);
        outputChannel.appendLine(`ERRO: Ficheiro não existe: ${scriptPath}`);
        return;
    }

    // 2. Comando para executar (Windows usa 'python' ou 'py', Linux/Mac usa 'python3')
    // Se falhar, podes tentar mudar para "py" ou o caminho completo do executável
    const pythonExecutable = 'python'; 
    
    // --json-only é fundamental para recebermos apenas dados limpos
    const command = `"${pythonExecutable}" "${scriptPath}" "${filePath}" --json-only`;

    // 3. Executar o script
    // cwd: context.extensionPath garante que os imports do Python funcionam
    cp.exec(command, { cwd: path.join(context.extensionPath, 'backend') }, (err, stdout, stderr) => {
        if (err) {
            outputChannel.appendLine(`ERRO DE EXECUÇÃO: ${err.message}`);
            if (stderr) outputChannel.appendLine(`STDERR: ${stderr}`);
            return;
        }

        try {
            if (!stdout.trim()) {
                outputChannel.appendLine("Aviso: O scanner não retornou dados.");
                return;
            }

            // 4. Parse do JSON
            const vulnerabilities: Vulnerability[] = JSON.parse(stdout);
            outputChannel.appendLine(`Sucesso! Encontradas ${vulnerabilities.length} vulnerabilidades.`);

            // 5. Mapear para o VS Code
            const diagnostics: vscode.Diagnostic[] = vulnerabilities.map(vuln => {
                // VS Code linhas começam em 0, Python em 1
                const lineIndex = vuln.line > 0 ? vuln.line - 1 : 0;
                
                const range = new vscode.Range(lineIndex, 0, lineIndex, 1000);

                const diagnostic = new vscode.Diagnostic(
                    range,
                    `[${vuln.type}] ${vuln.description}`,
                    mapSeverity(vuln.severity)
                );
                
                diagnostic.source = 'Python Security Scanner';
                diagnostic.code = vuln.category;
                return diagnostic;
            });

            // 6. Atualizar o editor
            diagnosticCollection.set(document.uri, diagnostics);

        } catch (e) {
            outputChannel.appendLine(`ERRO JSON: Falha ao ler output do Python.`);
            outputChannel.appendLine(`Erro: ${e}`);
            outputChannel.appendLine(`Output recebido: ${stdout}`);
        }
    });
}

function mapSeverity(severity: string): vscode.DiagnosticSeverity {
    switch (severity) {
        case 'HIGH': return vscode.DiagnosticSeverity.Error;       // Vermelho
        case 'MEDIUM': return vscode.DiagnosticSeverity.Warning;   // Amarelo
        case 'LOW': return vscode.DiagnosticSeverity.Information;  // Azul
        default: return vscode.DiagnosticSeverity.Hint;
    }
}

export function deactivate() {}