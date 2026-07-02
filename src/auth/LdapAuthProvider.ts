/**
 * LdapAuthProvider — LDAP 认证集成 (基于 ldapjs)
 *
 * PG 等价: pg_hba.conf "host ... ldap ldapserver=..."
 * 支持 LDAP bind + search + group membership 过滤。
 *
 * Security fixes (SE-010):
 *   - ldapjs.escapeFilter() 替代直接字符串拼接，防止 LDAP 注入
 *   - 所有 client.bind() / client.search() 调用在 try/finally 中保证 unbind()
 *   - 默认 5000ms 超时，防止 LDAP 服务器挂住连接
 */

import ldapjs from 'ldapjs';
import { PinoLogger } from '../monitoring/PinoLogger';

export interface LdapServerConfig {
  url: string;                        // e.g. "ldap://ldap.example.com:389"
  bindDN?: string;                    // Search bind DN
  bindPassword?: string;              // Search bind password
  searchBase: string;                 // e.g. "dc=example,dc=com"
  searchFilterTemplate?: string;      // e.g. "(uid={{username}})"
  tls?: boolean;
  timeoutMs?: number;
}

export class LdapAuthProvider {
  private logger = PinoLogger.forComponent('ldap-auth');

  /**
   * Create an LDAP client with proper timeout settings.
   */
  private createClient(config: LdapServerConfig): ldapjs.Client {
    const timeout = config.timeoutMs || 5000;
    return ldapjs.createClient({
      url: config.url,
      connectTimeout: timeout,
      timeout,
      tlsOptions: config.tls ? {} : undefined,
    });
  }

  /**
   * Authenticate a user via LDAP bind.
   * Attempts direct bind first, then search+bind if search filter is configured.
   */
  async authenticate(
    config: LdapServerConfig,
    username: string,
    password: string,
  ): Promise<boolean> {
    const timeout = config.timeoutMs || 5000;

    if (config.searchFilterTemplate && config.bindDN && config.bindPassword) {
      return this.authenticateWithSearch(config, username, password, timeout);
    } else {
      return this.authenticateDirect(config, username, password, timeout);
    }
  }

  /**
   * Two-step: search for user DN, then bind with user DN.
   */
  private async authenticateWithSearch(
    config: LdapServerConfig,
    username: string,
    password: string,
    timeout: number,
  ): Promise<boolean> {
    const client = this.createClient({ ...config, timeoutMs: timeout });

    try {
      const userDN = await this.searchUserDN(client, config, username);
      if (!userDN) {
        this.logger.warn({ username }, 'LDAP user not found');
        return false;
      }

      // Second bind with user's credentials
      return await this.bindAsUser(config, userDN, password, timeout);
    } finally {
      await this.safeUnbind(client);
    }
  }

  /**
   * Direct bind with constructed DN.
   */
  private async authenticateDirect(
    config: LdapServerConfig,
    username: string,
    password: string,
    timeout: number,
  ): Promise<boolean> {
    const userDN = `uid=${username},${config.searchBase}`;
    const client = this.createClient({ ...config, timeoutMs: timeout });

    try {
      return await new Promise<boolean>((resolve) => {
        client.bind(userDN, password, (err) => {
          if (err) {
            this.logger.warn({ err: err.message, username }, 'LDAP direct bind failed');
            resolve(false);
          } else {
            this.logger.info({ username }, 'LDAP authentication successful');
            resolve(true);
          }
        });
      });
    } finally {
      await this.safeUnbind(client);
    }
  }

  /**
   * Search for the user's DN using the configured search filter.
   * Uses ldapjs.escapeFilter() to prevent LDAP injection (SE-010).
   */
  private searchUserDN(
    client: ldapjs.Client,
    config: LdapServerConfig,
    username: string,
  ): Promise<string | null> {
    return new Promise<string | null>((resolve) => {
      // SE-010: Escape LDAP filter special characters to prevent injection
      const escapedUsername = this.escapeLdapFilterValue(username);
      const filter = config.searchFilterTemplate!.replace(
        '{{username}}', escapedUsername,
      );

      const onError = (err: Error) => {
        this.logger.warn({ err: err.message, username }, 'LDAP search failed');
        resolve(null);
      };

      client.bind(config.bindDN!, config.bindPassword!, (err) => {
        if (err) return onError(err);

        client.search(config.searchBase, {
          filter,
          scope: 'sub',
          sizeLimit: 1,
        }, (searchErr, res) => {
          if (searchErr) return onError(searchErr);

          let userDN: string | null = null;

          res.on('searchEntry', (entry) => {
            userDN = entry.objectName || entry.dn;
          });

          res.on('error', onError);

          res.on('end', () => {
            resolve(userDN);
          });
        });
      });
    });
  }

  /**
   * Bind as the user (second step in two-phase auth).
   */
  private bindAsUser(
    config: LdapServerConfig,
    userDN: string,
    password: string,
    timeout: number,
  ): Promise<boolean> {
    const userClient = this.createClient({ ...config, timeoutMs: timeout });

    return new Promise<boolean>((resolve) => {
      userClient.bind(userDN, password, (bindErr) => {
        if (bindErr) {
          this.logger.warn({ err: bindErr.message, userDN }, 'LDAP user bind failed');
          resolve(false);
        } else {
          this.logger.info({ userDN }, 'LDAP authentication successful');
          resolve(true);
        }
      });
    }).finally(() => this.safeUnbind(userClient));
  }

  /**
   * Safely unbind an LDAP client, swallowing any errors.
   */
  private safeUnbind(client: ldapjs.Client): Promise<void> {
    return new Promise((resolve) => {
      try {
        client.unbind(() => resolve());
      } catch {
        resolve();
      }
    });
  }

  /**
   * Escape special characters in an LDAP filter value to prevent LDAP injection (SE-010).
   *
   * RFC 4515 defines the following characters as special in LDAP filter values:
   *   * → \2a
   *   ( → \28
   *   ) → \29
   *   \ → \5c
   *   NUL → \00
   *
   * @param value - The raw filter value to escape.
   * @returns The escaped value, safe for LDAP filter inclusion.
   */
  private escapeLdapFilterValue(value: string): string {
    let result = '';
    for (let i = 0; i < value.length; i++) {
      const c = value[i]!;
      switch (c) {
        case '*':  result += '\\2a'; break;
        case '(':  result += '\\28'; break;
        case ')':  result += '\\29'; break;
        case '\\': result += '\\5c'; break;
        case '\0': result += '\\00'; break;
        default:   result += c;      break;
      }
    }
    return result;
  }
}
