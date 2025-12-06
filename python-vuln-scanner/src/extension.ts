import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import { SidebarProvider, Vulnerability } from './SidebarProvider';

let diagnosticCollection: vscode.DiagnosticCollection;
let outputChannel: vscode.OutputChannel;
let sidebarProvider: SidebarProvider;
let isScannerEnabled = true;

export function activate(context: vscode.ExtensionContext) {
    outputChannel = vscode.window.createOutputChannel("Python Vuln Scanner");
    outputChannel.appendLine("Extension starting...");
    
    vscode.commands.executeCommand('setContext', 'pythonVulnScanner.enabled', true);

    diagnosticCollection = vscode.languages.createDiagnosticCollection('python-vuln-scanner');
    context.subscriptions.push(diagnosticCollection);

    sidebarProvider = new SidebarProvider();
    vscode.window.registerTreeDataProvider('vuln-scanner-view', sidebarProvider);


    context.subscriptions.push(
        vscode.commands.registerCommand('python-vuln-scanner.openSettings', () => {
            vscode.commands.executeCommand('workbench.action.openSettings', 'pythonVulnScanner');
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('python-vuln-scanner.disable', () => {
            isScannerEnabled = false;
            vscode.commands.executeCommand('setContext', 'pythonVulnScanner.enabled', false);
            sidebarProvider.setScannerState(false);
            diagnosticCollection.clear();
            vscode.window.showInformationMessage("Security Scanner: PAUSED");
        })
    );

    context.subscriptions.push(
        vscode.commands.registerCommand('python-vuln-scanner.enable', () => {
            isScannerEnabled = true;
            vscode.commands.executeCommand('setContext', 'pythonVulnScanner.enabled', true);
            sidebarProvider.setScannerState(true);
            
            if (vscode.window.activeTextEditor && vscode.window.activeTextEditor.document.languageId === 'python') {
                runScanner(vscode.window.activeTextEditor.document, context);
            }
            vscode.window.showInformationMessage("Security Scanner: ACTIVE");
        })
    );

    // --- EVENTOS ---

    context.subscriptions.push(
        vscode.workspace.onDidSaveTextDocument(document => {
            if (document.languageId === 'python' && isScannerEnabled) {
                runScanner(document, context);
            }
        })
    );

    context.subscriptions.push(
        vscode.window.onDidChangeActiveTextEditor(editor => {
            if (editor && editor.document.languageId === 'python' && isScannerEnabled) {
                runScanner(editor.document, context);
            }
        })
    );

    outputChannel.appendLine("Extension loaded successfully.");
}

function runScanner(document: vscode.TextDocument, context: vscode.ExtensionContext) {
    if (!isScannerEnabled) return;

    const scriptPath = path.join(context.extensionPath, 'backend', 'scanner.py');
    const filePath = document.fileName;
    
    const config = vscode.workspace.getConfiguration('pythonVulnScanner');
    const enableInjection = config.get<boolean>('analyzers.enableInjection') ?? true;
    const enableAuth = config.get<boolean>('analyzers.enableAuth') ?? true;
    const enableLogging = config.get<boolean>('analyzers.enableLogging') ?? true;
    const enableDependencies = config.get<boolean>('analyzers.enableDependencies') ?? true;
    const enableTaint = config.get<boolean>('engine.enableTaintAnalysis') ?? true;

    outputChannel.appendLine(`--- Analyzing: ${filePath} ---`);

    if (!fs.existsSync(scriptPath)) {
        vscode.window.showErrorMessage(`CRITICAL ERROR: Scanner not found at: ${scriptPath}`);
        return;
    }

    const pythonExecutable = 'python'; 
    let args = `"${filePath}" --json-only`;

    if (!enableInjection) args += " --skip-injection";
    if (!enableAuth) args += " --skip-auth";
    if (!enableLogging) args += " --skip-logging";
    if (!enableDependencies) args += " --skip-dependencies";
    if (!enableTaint) args += " --no-taint";

    const command = `"${pythonExecutable}" "${scriptPath}" ${args}`;

    cp.exec(command, { cwd: path.join(context.extensionPath, 'backend') }, (err, stdout, stderr) => {
        if (err) {
            outputChannel.appendLine(`EXECUTION ERROR: ${err.message}`);
            return;
        }

        try {
            if (!stdout.trim()) return;

            const vulnerabilities: Vulnerability[] = JSON.parse(stdout);
            
            if (isScannerEnabled) {
                sidebarProvider.refresh(vulnerabilities);
            
                const diagnostics: vscode.Diagnostic[] = vulnerabilities.map(vuln => {
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

                diagnosticCollection.set(document.uri, diagnostics);
            }

        } catch (e) {
            outputChannel.appendLine(`JSON ERROR: ${e}`);
        }
    });
}

function mapSeverity(severity: string): vscode.DiagnosticSeverity {
    switch (severity) {
        case 'HIGH': return vscode.DiagnosticSeverity.Error;
        case 'MEDIUM': return vscode.DiagnosticSeverity.Warning;
        case 'LOW': return vscode.DiagnosticSeverity.Information;
        default: return vscode.DiagnosticSeverity.Hint;
    }
}

export function deactivate() {}