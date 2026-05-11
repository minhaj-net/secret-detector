import * as assert from 'assert';
import * as vscode from 'vscode';

suite('Secrets Detector Test Suite', () => {
  vscode.window.showInformationMessage('Starting Secrets Detector Tests...');

  // ✅ Test 1: AWS Key detect হচ্ছে কিনা
  test('Should detect AWS Access Key', async () => {
    const doc = await vscode.workspace.openTextDocument({
      content: 'const key = "AKIAIOSFODNN7EXAMPLE1234";',
      language: 'javascript'
    });
    await vscode.window.showTextDocument(doc);
    await new Promise(resolve => setTimeout(resolve, 1000));

    const diagnostics = vscode.languages.getDiagnostics(doc.uri);
    assert.strictEqual(diagnostics.length > 0, true, 'AWS Key should be detected');
  });

  // ✅ Test 2: GitHub Token detect হচ্ছে কিনা
  test('Should detect GitHub Token', async () => {
    const doc = await vscode.workspace.openTextDocument({
      content: 'const token = "ghp_abcdefghijklmnopqrstuvwxyz123456789";',
      language: 'javascript'
    });
    await vscode.window.showTextDocument(doc);
    await new Promise(resolve => setTimeout(resolve, 1000));

    const diagnostics = vscode.languages.getDiagnostics(doc.uri);
    assert.strictEqual(diagnostics.length > 0, true, 'GitHub Token should be detected');
  });

  // ✅ Test 3: Normal code এ false positive নেই
  test('Should not detect secrets in normal code', async () => {
    const doc = await vscode.workspace.openTextDocument({
      content: 'const name = "John"; const age = 25;',
      language: 'javascript'
    });
    await vscode.window.showTextDocument(doc);
    await new Promise(resolve => setTimeout(resolve, 1000));

    const diagnostics = vscode.languages.getDiagnostics(doc.uri);
    assert.strictEqual(diagnostics.length, 0, 'No secrets should be detected');
  });

  // ✅ Test 4: MongoDB URL detect হচ্ছে কিনা
  test('Should detect MongoDB connection string', async () => {
    const doc = await vscode.workspace.openTextDocument({
      content: 'const db = "mongodb://user:password@localhost:27017/mydb";',
      language: 'javascript'
    });
    await vscode.window.showTextDocument(doc);
    await new Promise(resolve => setTimeout(resolve, 1000));

    const diagnostics = vscode.languages.getDiagnostics(doc.uri);
    assert.strictEqual(diagnostics.length > 0, true, 'MongoDB URL should be detected');
  });

  // ✅ Test 5: OpenAI Key detect হচ্ছে কিনা
  test('Should detect OpenAI API Key', async () => {
    const doc = await vscode.workspace.openTextDocument({
      content: 'const key = "sk-abcdefghijklmnopqrstuvwxyz1234567890";',
      language: 'javascript'
    });
    await vscode.window.showTextDocument(doc);
    await new Promise(resolve => setTimeout(resolve, 1000));

    const diagnostics = vscode.languages.getDiagnostics(doc.uri);
    assert.strictEqual(diagnostics.length > 0, true, 'OpenAI Key should be detected');
  });
});