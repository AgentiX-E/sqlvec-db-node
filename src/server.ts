/**
 * SqlVec Database Server — Entry point
 *
 * Development mode (single-node, no Raft):
 *   npx tsx src/server.ts
 *
 * Production mode (multi-node Raft cluster):
 *   # Set env vars for TLS + peers first
 *   SQLVEC_SINGLE_NODE=false SQLVEC_SEED_NODES=... node dist/server.js
 */

import { PinoLogger } from './monitoring/PinoLogger';
import { SqlVecDatabase } from './core/SqlVecDatabase';
import * as fs from 'fs';

const logger = PinoLogger.forComponent('server');

function readPemOrFile(val: string | undefined): string {
  if (!val) return '';
  // Already PEM content
  if (val.startsWith('-----BEGIN')) return val;
  // Try as file path
  try { return fs.readFileSync(val, 'utf-8'); } catch { return val; }
}

async function main(): Promise<void> {
  const isSingleNode = process.env.SQLVEC_SINGLE_NODE !== 'false';
  const dataDir = process.env.SQLVEC_DATA_DIR || '/tmp/sqlvec-dev-data';
  fs.mkdirSync(dataDir, { recursive: true });

  const seedNodes = (process.env.SQLVEC_SEED_NODES || '').split(',').filter(Boolean);

  const config: any = {
    singleNode: isSingleNode || seedNodes.length === 0,
    cluster: {
      clusterName: process.env.SQLVEC_CLUSTER_NAME || 'dev',
      nodeId: process.env.SQLVEC_NODE_ID || 'dev-0',
      listenHost: process.env.SQLVEC_LISTEN_HOST || '0.0.0.0',
      pgPort: parseInt(process.env.SQLVEC_PG_PORT || '5432', 10),
      zmqPort: parseInt(process.env.SQLVEC_ZMQ_PORT || '15555', 10),
      raftPort: process.env.SQLVEC_RAFT_PORT ? parseInt(process.env.SQLVEC_RAFT_PORT, 10) : undefined,
      datacenter: process.env.SQLVEC_DC || 'dc1',
      shardCount: parseInt(process.env.SQLVEC_SHARD_COUNT || '1', 10),
      replicationFactor: parseInt(process.env.SQLVEC_REPLICATION_FACTOR || '1', 10),
      seedNodes,
      dataDir,
      metricsPort: process.env.SQLVEC_METRICS_PORT ? parseInt(process.env.SQLVEC_METRICS_PORT, 10) : 9464,
      metricsHost: process.env.SQLVEC_METRICS_HOST || '127.0.0.1',
    },
    tls: {
      // Read PEM from file path if env var is a path, or use directly if PEM
      cert: readPemOrFile(process.env.SQLVEC_TLS_CERT),
      key: readPemOrFile(process.env.SQLVEC_TLS_KEY),
      ca: readPemOrFile(process.env.SQLVEC_TLS_CA),
    },
    vector: {
      enabled: process.env.SQLVEC_VECTOR_ENABLED !== 'false',
      dimension: parseInt(process.env.SQLVEC_VECTOR_DIMENSION || '768', 10),
    },
    healthCheck: {
      port: process.env.SQLVEC_HEALTH_PORT ? parseInt(process.env.SQLVEC_HEALTH_PORT, 10) : 9090,
      host: '127.0.0.1',
    },
  };

  if (!isSingleNode && seedNodes.length > 0) {
    const mode = config.singleNode ? 'single-node' : 'multi-node';
    logger.info(`[SqlVec] Starting in ${mode} mode, seedNodes=${seedNodes.join(',')}`);
  }

  const db = new SqlVecDatabase(config);

  process.on('SIGINT', async () => {
    logger.info('Received SIGINT, shutting down...');
    await db.stop();
    process.exit(0);
  });

  process.on('SIGTERM', async () => {
    logger.info('Received SIGTERM, shutting down...');
    await db.stop();
    process.exit(0);
  });

  try {
    await db.start();
    logger.info(`✅ SqlVec started, listening on port ${db.getConfig().cluster.pgPort}`);
  } catch (err) {
    const e = err as Error;
    logger.error(`❌ Failed to start SqlVec: ${e.message}`);
    logger.error({ stack: e.stack }, 'Stack trace:');
    process.exit(1);
  }
}

main();
