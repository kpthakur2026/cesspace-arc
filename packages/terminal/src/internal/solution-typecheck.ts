#!/usr/bin/env node
/**
 * Server-owned deterministic TypeScript solution verification entrypoint.
 *
 * Traverses solution-style and referenced TypeScript projects without disk mutations:
 * - Emits declarations and build metadata into memory only (virtualized filesystem host).
 * - Leaves source files, JS/DTS outputs, and .tsbuildinfo files completely untouched on disk.
 * - Rejects any caller-supplied arguments or flags beyond authorized defaults ('--noEmit').
 * - Operates strictly on tsconfig.json in the current working directory.
 * @internal
 */

import fs from 'node:fs';
import path from 'node:path';
import ts from 'typescript';

function run(): void {
  // Validate caller arguments (fail closed on any unauthorized flag or path injection)
  const authorizedArgs = new Set(['--noEmit']);
  for (const arg of process.argv.slice(2)) {
    if (!authorizedArgs.has(arg)) {
      process.stderr.write(`Unauthorized argument for solution typecheck: '${arg}'\n`);
      process.exitCode = 1;
      return;
    }
  }

  const rootConfigPath = path.resolve(process.cwd(), 'tsconfig.json');
  if (!fs.existsSync(rootConfigPath)) {
    process.stderr.write(`error TS5083: Cannot read file '${rootConfigPath}': File not found.\n`);
    process.exitCode = 1;
    return;
  }

  // Pure in-memory virtual storage for declaration files, emitted JS, and buildinfo.
  // This guarantees zero disk writes during type checking while allowing downstream
  // referenced projects to resolve in-memory upstream types.
  const virtualFiles = new Map<string, string>();
  const virtualTimestamps = new Map<string, Date>();

  const formatHost: ts.FormatDiagnosticsHost = {
    getCurrentDirectory: () => process.cwd(),
    getCanonicalFileName: (f) => f,
    getNewLine: () => '\n',
  };

  const reportDiagnostic = (diagnostic: ts.Diagnostic) => {
    const formatted = ts.formatDiagnosticsWithColorAndContext([diagnostic], formatHost);
    process.stdout.write(formatted);
  };

  const host = ts.createSolutionBuilderHost(
    ts.sys,
    undefined,
    reportDiagnostic,
    undefined,
    (errorCount) => {
      if (errorCount > 0) {
        process.stdout.write(`\nFound ${errorCount} error${errorCount === 1 ? '' : 's'}.\n`);
      }
    },
  );

  // Virtualize write: strictly in-memory Map, never write to disk
  host.writeFile = (fileName: string, content: string) => {
    const resolved = path.resolve(fileName);
    virtualFiles.set(resolved, content);
    virtualTimestamps.set(resolved, new Date());
  };

  // Virtualize read: check in-memory Map first before delegating to disk
  const originalReadFile = host.readFile.bind(host);
  host.readFile = (fileName: string, encoding?: string) => {
    const resolved = path.resolve(fileName);
    if (virtualFiles.has(resolved)) {
      return virtualFiles.get(resolved);
    }
    return originalReadFile(fileName, encoding);
  };

  // Virtualize fileExists: check in-memory Map first
  const originalFileExists = host.fileExists.bind(host);
  host.fileExists = (fileName: string) => {
    const resolved = path.resolve(fileName);
    if (virtualFiles.has(resolved)) {
      return true;
    }
    return originalFileExists(fileName);
  };

  // Virtualize directoryExists: check virtual file paths
  const originalDirectoryExists = host.directoryExists?.bind(host);
  if (originalDirectoryExists) {
    host.directoryExists = (dirName: string) => {
      const resolvedDir = path.resolve(dirName);
      for (const vFile of virtualFiles.keys()) {
        if (vFile.startsWith(resolvedDir + path.sep)) {
          return true;
        }
      }
      return originalDirectoryExists(dirName);
    };
  }

  // Virtualize modified time: return virtual timestamp if file was virtually written
  const originalGetModifiedTime = host.getModifiedTime?.bind(host);
  if (originalGetModifiedTime) {
    host.getModifiedTime = (fileName: string) => {
      const resolved = path.resolve(fileName);
      if (virtualTimestamps.has(resolved)) {
        return virtualTimestamps.get(resolved);
      }
      return originalGetModifiedTime(fileName);
    };
  }

  // Pure check-only protection: prohibit disk mutations
  host.createDirectory = () => {
    // In-memory virtualization: never create directories on disk
  };
  host.deleteFile = (fileName: string) => {
    const resolved = path.resolve(fileName);
    virtualFiles.delete(resolved);
    virtualTimestamps.delete(resolved);
  };
  host.setModifiedTime = () => {
    // Never mutate file timestamps on disk
  };

  try {
    const builder = ts.createSolutionBuilder(host, [rootConfigPath], {});
    const exitStatus = builder.build();
    if (exitStatus !== ts.ExitStatus.Success) {
      process.exitCode = 1;
    } else {
      process.exitCode = 0;
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`Internal typecheck error: ${message}\n`);
    process.exitCode = 1;
  }
}

run();
