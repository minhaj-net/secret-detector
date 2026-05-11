import * as vscode from "vscode";

//  Secret patterns যেগুলো detect করবে
const SECRET_PATTERNS: { name: string; pattern: RegExp }[] = [
  //  Cloud Provider Keys
  { name: "AWS Access Key", pattern: /AKIA[0-9A-Z]{16}/g },
  { name: "AWS Secret Key", pattern: /aws_secret_access_key\s*=\s*[^\s]+/gi },
  { name: "Google API Key", pattern: /AIza[0-9A-Za-z\-_]{35}/g },
  { name: "Firebase URL", pattern: /https:\/\/[a-z0-9-]+\.firebaseio\.com/gi },
  { name: "Azure Storage Key", pattern: /DefaultEndpointsProtocol=https;AccountName=.*;AccountKey=.*;/gi },
  { name: "DigitalOcean Token", pattern: /dop_v1_[a-zA-Z0-9]{60,}/g },
  { name: "Cloudinary URL", pattern: /cloudinary:\/\/[0-9]+:[a-zA-Z0-9_-]+@[a-z]+/gi },
  { name: "Heroku API Key", pattern: /heroku[a-z0-9]{20,}/gi },

  //  Git & DevOps Tokens
  { name: "GitHub Token", pattern: /ghp_[a-zA-Z0-9]{20,}/g },
  { name: "GitLab Token", pattern: /glpat-[a-zA-Z0-9\-_]{20,}/g },
  { name: "NPM Token", pattern: /npm_[a-zA-Z0-9]{36}/g },

  //  AI & Communication APIs
  { name: "OpenAI API Key", pattern: /sk-[a-zA-Z0-9]{20,}/g },
  { name: "Slack Token", pattern: /xox[baprs]-[a-zA-Z0-9-]{10,}/g },
  { name: "Discord Bot Token", pattern: /[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}/g },
  { name: "Telegram Bot Token", pattern: /\d{8,10}:[a-zA-Z0-9_-]{35}/g },
  { name: "Facebook Access Token", pattern: /EAACEdEose0cBA[0-9A-Za-z]+/g },
  { name: "Sendgrid API Key", pattern: /SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}/g },
  { name: "Mailgun API Key", pattern: /key-[0-9a-zA-Z]{32}/g },
  { name: "Twilio API Key", pattern: /SK[0-9a-fA-F]{32}/g },

  //  Payment APIs
  { name: "Stripe Secret Key", pattern: /sk_live_[a-zA-Z0-9]{24,}/g },
  { name: "Stripe Publishable Key", pattern: /pk_live_[0-9a-zA-Z]{24,}/g },

  // Database URLs
  { name: "MongoDB Connection String", pattern: /mongodb(\+srv)?:\/\/[^\s]+/gi },
  { name: "PostgreSQL URL", pattern: /postgres(ql)?:\/\/[^\s]+/gi },
  { name: "MySQL Connection String", pattern: /mysql:\/\/[^\s]+/gi },
  { name: "Redis URL", pattern: /redis:\/\/[^\s]+/gi },

  //  Private Keys & Certificates
  { name: "SSH Private Key", pattern: /-----BEGIN OPENSSH PRIVATE KEY-----/g },
  { name: "Generic Private Key", pattern: /-----BEGIN PRIVATE KEY-----/g },
  { name: "PGP Private Key", pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g },
  { name: "Private Key", pattern: /-----BEGIN (RSA|EC|PGP) PRIVATE KEY-----/g },

  // Auth & Generic Secrets
  { name: "Bearer Token", pattern: /Bearer\s+[a-zA-Z0-9\-._~+/]+=*/g },
  { name: "JWT Token", pattern: /eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+/g },
  { name: "OAuth Client Secret", pattern: /client_secret\s*[:=]\s*["'][^"']+["']/gi },
  { name: "Hardcoded Password", pattern: /password\s*=\s*["'][^"']{4,}["']/gi },
  { name: "Hardcoded Secret", pattern: /secret\s*=\s*["'][^"']{4,}["']/gi },
  { name: "Generic API Key", pattern: /api[_-]?key\s*[:=]\s*["'][a-zA-Z0-9_\-]{16,}["']/gi },
  { name: "Generic Secret Token", pattern: /(secret|token|auth)[_-]?(key|token)?\s*[:=]\s*["'][^"']{8,}["']/gi },

  //  Extra Cloud & Infrastructure
  { name: "AWS Session Token", pattern: /aws_session_token\s*=\s*[^\s]+/gi },
  { name: "GCP Service Account", pattern: /"type":\s*"service_account"/g },
  { name: "Vault Token", pattern: /s\.[a-zA-Z0-9]{24}/g },
  { name: "Terraform Cloud Token", pattern: /[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9]{60,}/g },

  //  Developer Tools
  { name: "Sentry DSN", pattern: /https:\/\/[a-f0-9]+@[a-z0-9.]+\.sentry\.io\/[0-9]+/g },

  //  Social Media
  { name: "Twitter Bearer Token", pattern: /AAAAAAAAAA[a-zA-Z0-9%]+/g },
  { name: "Instagram Token", pattern: /IGQVJXb[a-zA-Z0-9_-]+/g },
  { name: "LinkedIn Token", pattern: /AQX[a-zA-Z0-9_-]{50,}/g },

  //  Extra Payment
  { name: "Razorpay Key", pattern: /rzp_(live|test)_[a-zA-Z0-9]{14}/g },
  { name: "Braintree Token", pattern: /access_token\$production\$[a-zA-Z0-9]+/g },
  { name: "PayPal Secret", pattern: /paypal.*secret\s*[:=]\s*["'][^"']+["']/gi },

  // Hosting & CDN
  { name: "Cloudflare API Key", pattern: /cloudflare.*[a-zA-Z0-9_-]{37}/gi },
  { name: "Netlify Token", pattern: /netlify.*[a-zA-Z0-9]{40,}/gi },

  // Email Services
  { name: "Postmark Token", pattern: /[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12}/g },

];

// ✅ Decoration (লাল আন্ডারলাইন) তৈরি করো
const decorationType = vscode.window.createTextEditorDecorationType({
  backgroundColor: "rgba(255,0,0,0.2)",
  border: "1px solid red",
  borderRadius: "2px",
});

// ✅ কোনো file এ secret আছে কিনা check করো
function detectSecrets(document: vscode.TextDocument): vscode.Diagnostic[] {
  const diagnostics: vscode.Diagnostic[] = [];
  const text = document.getText();

  for (const { name, pattern } of SECRET_PATTERNS) {
    let match;
    pattern.lastIndex = 0;

    while ((match = pattern.exec(text)) !== null) {
      const startPos = document.positionAt(match.index);
      const endPos = document.positionAt(match.index + match[0].length);
      const range = new vscode.Range(startPos, endPos);

      const diagnostic = new vscode.Diagnostic(
        range,
        `🔐 Secrets Detector: "${name}" detected! Remove this before committing.`,
        vscode.DiagnosticSeverity.Error
      );
      diagnostic.source = "Secrets Detector";
      diagnostics.push(diagnostic);
    }
  }

  return diagnostics;
}

// ✅ Extension activate হলে এটা চলে
export function activate(context: vscode.ExtensionContext) {
  console.log("🔐 Secrets Detector is now active!");

  const diagnosticCollection =
    vscode.languages.createDiagnosticCollection("secrets-detector");

  // যেকোনো file open বা edit হলে check করো
  const runDetection = (document: vscode.TextDocument) => {
    const diagnostics = detectSecrets(document);
    diagnosticCollection.set(document.uri, diagnostics);

    if (diagnostics.length > 0) {
      vscode.window.showWarningMessage(
        `🔐 Secrets Detector: ${diagnostics.length} secret(s) found in ${document.fileName.split("\\").pop()}!`
      );
    }
  };

  // File open হলে
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument(runDetection)
  );

  // File edit হলে
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((e) => runDetection(e.document))
  );

  // File save হলে
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(runDetection)
  );

  // Manual scan command
  context.subscriptions.push(
    vscode.commands.registerCommand("secrets-detector.scan", () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        runDetection(editor.document);
        vscode.window.showInformationMessage("🔍 Scan complete!");
      }
    })
  );

  context.subscriptions.push(diagnosticCollection);
}

export function deactivate() {}