import type {
  ListDirectoryRequest,
  ListDirectoryResponse,
  ReadFileRequest,
  ReadFileResponse,
  SearchFilesRequest,
  SearchFilesResponse,
  SearchTextRequest,
  SearchTextResponse,
} from '@cesspace-arc/protocol';

/**
 * Interface definition for Jailed Filesystem Subsystem.
 * Implementation target: RC-01 (read-only) & RC-03 (mutation).
 */
export interface IFilesystemSubsystem {
  resolveSecurePath(workspaceRoot: string, requestedPath: string): Promise<string>;
  listDirectory(
    workspaceRoot: string,
    request: ListDirectoryRequest,
  ): Promise<ListDirectoryResponse>;
  readFile(workspaceRoot: string, request: ReadFileRequest): Promise<ReadFileResponse>;
  searchFiles(workspaceRoot: string, request: SearchFilesRequest): Promise<SearchFilesResponse>;
  searchText(workspaceRoot: string, request: SearchTextRequest): Promise<SearchTextResponse>;
}
