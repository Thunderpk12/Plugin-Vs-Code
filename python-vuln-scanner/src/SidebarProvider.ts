import * as vscode from 'vscode';

export interface Vulnerability {
    line: number;
    column: number;
    type: string;
    description: string;
    severity: string;
    category: string;
}

// Mapa de Nomes Completos para Categorias OWASP
const CATEGORY_NAMES: { [key: string]: string } = {
    'A03': 'A03: Injection',
    'A06': 'A06: Vulnerable Components',
    'A07': 'A07: Identification & Auth Failures',
    'A09': 'A09: Logging & Monitoring Failures'
};

export class SidebarProvider implements vscode.TreeDataProvider<VulnItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<VulnItem | undefined | null | void> = new vscode.EventEmitter<VulnItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<VulnItem | undefined | null | void> = this._onDidChangeTreeData.event;

    private vulnerabilities: Vulnerability[] = [];
    private isEnabled: boolean = true;

    refresh(vulns: Vulnerability[]): void {
        this.vulnerabilities = vulns;
        this._onDidChangeTreeData.fire();
    }

    setScannerState(enabled: boolean) {
        this.isEnabled = enabled;
        if (!enabled) {
            this.vulnerabilities = [];
        }
        this._onDidChangeTreeData.fire();
    }

    getTreeItem(element: VulnItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: VulnItem): Thenable<VulnItem[]> {
        // Estado: Desligado
        if (!this.isEnabled) {
            return Promise.resolve([
                new VulnItem("Scanner Paused", "status", vscode.TreeItemCollapsibleState.None, undefined, undefined, "Click the 'Play' button to resume analysis.")
            ]);
        }

        if (!element) {
            // NÍVEL 1: CATEGORIAS (Com nomes completos)
            const categories = Array.from(new Set(this.vulnerabilities.map(v => v.category))).sort();
            
            if (categories.length === 0) {
                return Promise.resolve([new VulnItem("No vulnerabilities detected", "empty", vscode.TreeItemCollapsibleState.None)]);
            }

            return Promise.resolve(categories.map(cat => {
                const count = this.vulnerabilities.filter(v => v.category === cat).length;
                // Traduz o código (ex: A07) para o nome completo
                const fullName = CATEGORY_NAMES[cat] || cat;
                return new VulnItem(`${fullName} (${count})`, "categoria", vscode.TreeItemCollapsibleState.Expanded);
            }));
        } else {
            // NÍVEL 2: ITENS
            if (element.contextValue === "categoria") {
                // Extrai o código "A03" do início da string "A03: Injection..."
                const categoryCode = element.label.split(':')[0]; 
                const filtered = this.vulnerabilities.filter(v => v.category === categoryCode);
                
                return Promise.resolve(filtered.map(v => {
                    return new VulnItem(
                        `${v.type}`, 
                        "item", 
                        vscode.TreeItemCollapsibleState.None,
                        { 
                            command: 'vscode.open',
                            title: 'Open File',
                            arguments: [vscode.window.activeTextEditor?.document.uri, { selection: new vscode.Range(v.line - 1, 0, v.line - 1, 0) }]
                        },
                        v.severity,
                        v.description,
                        `Line ${v.line}`
                    );
                }));
            }
        }
        return Promise.resolve([]);
    }
}

class VulnItem extends vscode.TreeItem {
    constructor(
        public readonly label: string,
        private type: string,
        public readonly collapsibleState: vscode.TreeItemCollapsibleState,
        public readonly command?: vscode.Command,
        public readonly severity?: string,
        public readonly descText?: string,
        public readonly shortDesc?: string
    ) {
        super(label, collapsibleState);
        
        this.contextValue = type; 
        
        if (descText) {
            this.tooltip = new vscode.MarkdownString(`**${label}**\n\n${descText}`);
        } else {
            this.tooltip = label;
        }

        if (shortDesc) {
            this.description = shortDesc;
        }
        
        // --- ÍCONES ---
        if (type === "item") {
            if (severity === 'HIGH') {
                this.iconPath = new vscode.ThemeIcon('error', new vscode.ThemeColor('testing.iconFailed')); 
            } else if (severity === 'MEDIUM') {
                this.iconPath = new vscode.ThemeIcon('warning', new vscode.ThemeColor('testing.iconQueued')); 
            } else {
                this.iconPath = new vscode.ThemeIcon('info');
            }
        } 
        else if (type === "categoria") {
            const catCode = label.split(':')[0]; // Apanha o código antes dos dois pontos
            
            switch (catCode) {
                case 'A03': 
                    this.iconPath = new vscode.ThemeIcon('symbol-variable', new vscode.ThemeColor('charts.red')); 
                    break;
                case 'A06': 
                    this.iconPath = new vscode.ThemeIcon('package', new vscode.ThemeColor('charts.orange')); 
                    break;
                case 'A07': 
                    this.iconPath = new vscode.ThemeIcon('key', new vscode.ThemeColor('charts.yellow')); 
                    break;
                case 'A09': 
                    this.iconPath = new vscode.ThemeIcon('output', new vscode.ThemeColor('charts.blue')); 
                    break;
                default:
                    this.iconPath = new vscode.ThemeIcon('shield'); 
            }
        }
        else if (type === "status") {
            this.iconPath = new vscode.ThemeIcon('circle-slash');
        }
        else if (type === "empty") {
            this.iconPath = new vscode.ThemeIcon('check');
        }
    }
}