import { generateKeyPairSync } from 'node:crypto';
import { execFile as execFileCallback, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { pathToFileURL } from 'node:url';
import {
  MANIFEST_FILE,
  SIGNATURE_FILE,
  canonicalJson,
  signManifest,
} from '../../scripts/arc10-distribution-lib.mjs';

const execFile = promisify(execFileCallback);

export function createSigningKeyPair() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    privateKey: privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    publicKey: publicKey.export({ format: 'pem', type: 'spki' }).toString(),
  };
}

export async function createCleanSourceFixture(repositoryRoot) {
  const root = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'arc10-source-'));
  await fs.promises.cp(repositoryRoot, root, {
    recursive: true,
    filter(source) {
      const relative = path.relative(repositoryRoot, source);
      if (!relative) return true;
      const parts = relative.split(path.sep);
      return !parts.some((part) => ['.git', 'node_modules', 'dist'].includes(part));
    },
  });
  await execFile('git', ['init', '--quiet'], { cwd: root });
  await execFile('git', ['config', 'user.name', 'ARC Distribution Test'], { cwd: root });
  await execFile('git', ['config', 'user.email', 'arc-distribution@example.invalid'], {
    cwd: root,
  });
  await execFile('git', ['add', '.'], { cwd: root });
  await execFile('git', ['commit', '--quiet', '-m', 'test source snapshot'], { cwd: root });
  await attachInstalledDependencies(repositoryRoot, root);
  return root;
}

export async function attachInstalledDependencies(repositoryRoot, fixtureRoot) {
  await fs.promises.symlink(
    path.join(repositoryRoot, 'node_modules'),
    path.join(fixtureRoot, 'node_modules'),
  );
}

export async function cloneDirectory(source) {
  const destination = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'arc10-bundle-'));
  await fs.promises.cp(source, destination, { recursive: true });
  return destination;
}

export async function resignBundle(bundleDir, privateKey, mutate) {
  const manifestPath = path.join(bundleDir, MANIFEST_FILE);
  const manifest = JSON.parse(await fs.promises.readFile(manifestPath, 'utf8'));
  await mutate(manifest);
  const bytes = Buffer.from(`${canonicalJson(manifest)}\n`);
  await fs.promises.writeFile(manifestPath, bytes);
  await fs.promises.writeFile(
    path.join(bundleDir, SIGNATURE_FILE),
    `${signManifest(bytes, privateKey)}\n`,
  );
}

export class InstalledStdioClient {
  constructor(serverFile, workspace) {
    const auditRoot = fs.mkdtempSync(path.join(path.dirname(workspace), 'installed-audit-'));
    const keyRoot = path.join(auditRoot, 'keys');
    fs.mkdirSync(keyRoot, { recursive: true, mode: 0o700 });
    fs.chmodSync(auditRoot, 0o700);
    fs.chmodSync(keyRoot, 0o700);
    const auditKeys = generateKeyPairSync('ed25519');
    const signingKeyPath = path.join(keyRoot, 'signing.pem');
    const publicKeyPath = path.join(keyRoot, 'public.pem');
    fs.writeFileSync(
      signingKeyPath,
      auditKeys.privateKey.export({ format: 'pem', type: 'pkcs8' }),
      { mode: 0o600 },
    );
    fs.writeFileSync(publicKeyPath, auditKeys.publicKey.export({ format: 'pem', type: 'spki' }), {
      mode: 0o600,
    });
    fs.chmodSync(signingKeyPath, 0o600);
    fs.chmodSync(publicKeyPath, 0o600);
    const runner = `
      const { createArcMcpServer } = await import(${JSON.stringify(pathToFileURL(serverFile).href)});
      const server = createArcMcpServer({
        transport: 'stdio',
        authorizedRoots: [{ id: 'workspace', path: ${JSON.stringify(workspace)} }],
        defaultWorkspaceId: 'workspace',
        audit: {
          directory: ${JSON.stringify(path.join(auditRoot, 'store'))},
          signingKeyPath: ${JSON.stringify(signingKeyPath)},
          publicKeyPath: ${JSON.stringify(publicKeyPath)}
        }
      });
      await server.start();
    `;
    this.proc = spawn(process.execPath, ['--input-type=module', '-e', runner], {
      cwd: workspace,
      env: { ...process.env, CESSPACE_WORKSPACE: workspace },
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    this.id = 0;
    this.pending = new Map();
    this.buffer = '';
    this.stderr = '';
    this.proc.stderr.on('data', (chunk) => {
      this.stderr += chunk.toString('utf8');
    });
    this.proc.on('close', () => {
      for (const [id, waiter] of this.pending) {
        this.pending.delete(id);
        waiter.reject(new Error(`Installed MCP server exited: ${this.stderr}`));
      }
    });
    this.proc.stdout.on('data', (chunk) => {
      this.buffer += chunk.toString('utf8');
      let newline = this.buffer.indexOf('\n');
      while (newline !== -1) {
        const line = this.buffer.slice(0, newline).trim();
        this.buffer = this.buffer.slice(newline + 1);
        if (line) {
          const message = JSON.parse(line);
          const waiter = this.pending.get(message.id);
          if (waiter) {
            this.pending.delete(message.id);
            waiter.resolve(message);
          }
        }
        newline = this.buffer.indexOf('\n');
      }
    });
  }

  request(method, params = {}) {
    const id = ++this.id;
    const payload = `${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`Installed MCP request timed out: ${this.stderr}`));
      }, 10_000);
      this.pending.set(id, {
        resolve(value) {
          clearTimeout(timer);
          resolve(value);
        },
        reject(error) {
          clearTimeout(timer);
          reject(error);
        },
      });
      this.proc.stdin.write(payload);
    });
  }

  notify(method, params = {}) {
    this.proc.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method, params })}\n`);
  }

  async health() {
    const initialized = await this.request('initialize', {
      protocolVersion: '2025-11-25',
      capabilities: {},
      clientInfo: { name: 'arc10-installed-fixture', version: '1.0.0' },
    });
    if (initialized.error) throw new Error(JSON.stringify(initialized.error));
    this.notify('notifications/initialized');
    const response = await this.request('tools/call', { name: 'health', arguments: {} });
    if (response.error) throw new Error(JSON.stringify(response.error));
    const text = response.result.content.find((item) => item.type === 'text')?.text;
    return JSON.parse(text);
  }

  async close() {
    this.proc.stdin.end();
    if (this.proc.exitCode !== null) return;
    await new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.proc.kill('SIGKILL');
        resolve();
      }, 3000);
      this.proc.once('exit', () => {
        clearTimeout(timer);
        resolve();
      });
    });
  }
}
