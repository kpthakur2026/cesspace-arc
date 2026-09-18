import {
  openSync,
  closeSync,
  writeSync,
  fsyncSync,
  lstatSync,
  statSync,
  readFileSync,
  unlinkSync,
  linkSync,
  renameSync,
  realpathSync,
  type Stats,
} from 'node:fs';

/**
 * Interface abstracting raw filesystem I/O operations for the filesystem subsystem.
 * Allows deterministic failure and race injection in tests without monkey-patching globals.
 */
export interface IFilesystemOps {
  realpath(path: string): string;
  lstat(path: string): Stats;
  stat(path: string): Stats;
  readFile(path: string): Buffer;
  open(path: string, flags: string | number, mode?: number): number;
  close(fd: number): void;
  write(fd: number, buffer: Buffer): number;
  fsync(fd: number): void;
  unlink(path: string): void;
  link(existingPath: string, newPath: string): void;
  rename(oldPath: string, newPath: string): void;
}

/**
 * Standard production filesystem operations delegating to node:fs.
 */
export class NodeFilesystemOps implements IFilesystemOps {
  public realpath(path: string): string {
    return realpathSync(path);
  }

  public lstat(path: string): Stats {
    return lstatSync(path);
  }

  public stat(path: string): Stats {
    return statSync(path);
  }

  public readFile(path: string): Buffer {
    return readFileSync(path);
  }

  public open(path: string, flags: string | number, mode?: number): number {
    return openSync(path, flags, mode);
  }

  public close(fd: number): void {
    closeSync(fd);
  }

  public write(fd: number, buffer: Buffer): number {
    return writeSync(fd, buffer, 0, buffer.length);
  }

  public fsync(fd: number): void {
    fsyncSync(fd);
  }

  public unlink(path: string): void {
    unlinkSync(path);
  }

  public link(existingPath: string, newPath: string): void {
    linkSync(existingPath, newPath);
  }

  public rename(oldPath: string, newPath: string): void {
    renameSync(oldPath, newPath);
  }
}
