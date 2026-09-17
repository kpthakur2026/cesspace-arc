/**
 * CesSpace ARC — Model Context Protocol Server Entrypoint
 * Implementation target: RC-01 (stdio) & RC-05 (HTTP SSE).
 */

export interface ArcServerConfig {
  transport: 'stdio' | 'http';
  host?: string;
  port?: number;
  authorizedRoots: string[];
}

export interface IArcMcpServer {
  start(): Promise<void>;
  stop(): Promise<void>;
}
