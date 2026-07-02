/**
 * RadiusAuthProvider — RADIUS authentication via UDP PAP
 *
 * Implements RADIUS Access-Request / Access-Accept using Node.js dgram.
 * No external npm dependency needed — RADIUS PAP is a simple UDP exchange.
 *
 * PG equivalent: pg_hba.conf "host ... radius" method
 */

import * as dgram from 'dgram';
import * as crypto from 'crypto';
import { PinoLogger } from '../monitoring/PinoLogger';

const RADIUS_PORT = 1812;
const RADIUS_TIMEOUT = 5000;
const ACCESS_REQUEST = 1;
const ACCESS_ACCEPT = 2;
const ACCESS_REJECT = 3;

export interface RadiusServerConfig {
  host: string;
  secret: string;
  port?: number;
  timeoutMs?: number;
  /** NAS identifier sent in the request */
  nasIdentifier?: string;
}

export class RadiusAuthProvider {
  private logger = PinoLogger.forComponent('radius-auth');

  /**
   * Authenticate a user via RADIUS PAP.
   * Sends Access-Request to the RADIUS server, waits for Access-Accept.
   */
  async authenticate(
    config: RadiusServerConfig,
    username: string,
    password: string,
  ): Promise<boolean> {
    const port = config.port || RADIUS_PORT;
    const timeout = config.timeoutMs || RADIUS_TIMEOUT;

    return new Promise<boolean>((resolve) => {
      const socket = dgram.createSocket('udp4');
      const id = crypto.randomBytes(1)[0];
      const authenticator = crypto.randomBytes(16);
      const secret = Buffer.from(config.secret, 'utf8');

      // Build RADIUS packet attributes
      const attrs = Buffer.concat([
        this.encodeStringAttr(1, username),        // User-Name
        this.encodePasswordAttr(password, authenticator, secret),  // User-Password (PAP)
        this.encodeStringAttr(4, config.nasIdentifier || 'sqlvec'), // NAS-Identifier
      ]);

      // Build RADIUS packet
      const packet = Buffer.alloc(20 + attrs.length);
      packet[0] = ACCESS_REQUEST;     // Code
      packet[1] = id;                 // Packet identifier (was being written as 0 — P2 fix)
      packet.writeUInt16BE(20 + attrs.length, 2); // Length
      authenticator.copy(packet, 4);  // Authenticator (Request)
      attrs.copy(packet, 20);

      // Compute Request Authenticator (MD5(Code + ID + Length + RequestAuth + Attributes + Secret))
      const hashInput = Buffer.concat([
        packet.subarray(0, 4),  // Code + ID + Length
        authenticator,           // Request Authenticator
        attrs,
        secret,
      ]);
      const requestAuth = crypto.createHash('md5').update(hashInput).digest();
      requestAuth.copy(packet, 4);

      const timer = setTimeout(() => {
        socket.close();
        this.logger.warn({ username }, 'RADIUS authentication timeout');
        resolve(false);
      }, timeout);

      socket.on('message', (msg) => {
        clearTimeout(timer);
        socket.close();

        if (msg.length < 20) {
          this.logger.warn('RADIUS response too short');
          resolve(false);
          return;
        }

        const code = msg[0];
        if (code !== ACCESS_ACCEPT && code !== ACCESS_REJECT) {
          this.logger.warn({ code }, 'RADIUS unexpected response code');
          resolve(false);
          return;
        }

        // Verify Response Authenticator
        const responseAuth = msg.subarray(4, 20);
        const verifyInput = Buffer.concat([
          msg.subarray(0, 4),
          responseAuth,
          msg.subarray(20),
          secret,
        ]);
        const expected = crypto.createHash('md5').update(verifyInput).digest();

        // Standard RADIUS auth: we trust the packet if the authenticator matches
        const match = expected.equals(responseAuth);
        if (!match) {
          this.logger.warn('RADIUS response authenticator mismatch');
          resolve(false);
          return;
        }

        resolve(code === ACCESS_ACCEPT);
      });

      socket.on('error', (err: Error) => {
        clearTimeout(timer);
        socket.close();
        this.logger.error({ err: err.message }, 'RADIUS socket error');
        resolve(false);
      });

      socket.send(packet, port, config.host, (err) => {
        if (err) {
          clearTimeout(timer);
          socket.close();
          this.logger.error({ err: err.message }, 'RADIUS send failed');
          resolve(false);
        }
      });
    });
  }

  private encodeStringAttr(type: number, value: string): Buffer {
    const val = Buffer.from(value, 'utf8');
    const buf = Buffer.alloc(2 + val.length);
    buf[0] = type;
    buf[1] = 2 + val.length;
    val.copy(buf, 2);
    return buf;
  }

  /**
   * Encode User-Password attribute per RFC 2865 §5.2
   * PAP: XOR(password + padding, MD5(secret + authenticator + previous ciphertext))
   */
  private encodePasswordAttr(password: string, authenticator: Buffer, secret: Buffer): Buffer {
    const pwBuf = Buffer.from(password, 'utf8');
    // Pad to 16-byte blocks
    const paddedLen = Math.ceil(pwBuf.length / 16) * 16;
    const padded = Buffer.alloc(paddedLen);
    pwBuf.copy(padded);  // remaining null bytes are padding

    const encrypted = Buffer.alloc(paddedLen);
    const blockCount = paddedLen / 16;

    for (let i = 0; i < blockCount; i++) {
      const hashInput = (i === 0)
        ? Buffer.concat([secret, authenticator])
        : Buffer.concat([secret, encrypted.subarray((i - 1) * 16, i * 16)]);
      const hash = crypto.createHash('md5').update(hashInput).digest();

      for (let j = 0; j < 16; j++) {
        encrypted[i * 16 + j] = padded[i * 16 + j] ^ hash[j];
      }
    }

    const buf = Buffer.alloc(2 + 2 + encrypted.length); // type(2) + length + encrypted
    buf[0] = 2; // User-Password attribute type
    buf[1] = 2 + encrypted.length;
    encrypted.copy(buf, 2);
    return buf;
  }
}
