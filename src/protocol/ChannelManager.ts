/**
 * ChannelManager — PostgreSQL LISTEN/NOTIFY channel management.
 *
 * Implements the pg LISTEN/NOTIFY protocol semantics:
 *   - LISTEN <channel>: subscribe to a notification channel
 *   - UNLISTEN <channel>: unsubscribe from a channel
 *   - UNLISTEN *: unsubscribe from all channels
 *   - NOTIFY <channel>, <payload>: send a notification to all subscribers
 *
 * Each channel can have multiple session subscribers. Session cleanup
 * is handled by unlistenAll on disconnect.
 *
 * @module protocol/ChannelManager
 */

import { PinoLogger } from '../monitoring/PinoLogger';

const channelLogger = PinoLogger.forComponent('ChannelManager');

export interface NotificationEvent {
  sessionId: string;
  channel: string;
  payload: string;
}

export class ChannelManager {
  /** channel name → set of subscribed sessionIds */
  private channels = new Map<string, Set<string>>();
  /** sessionId → set of subscribed channel names (for cleanup) */
  private sessionChannels = new Map<string, Set<string>>();

  /**
   * Subscribe a session to a channel.
   * @returns true if this is a new subscription (session wasn't already listening)
   */
  listen(channel: string, sessionId: string): boolean {
    // Normalize channel name (lowercase per PG spec)
    const normChannel = channel.toLowerCase();

    if (!this.channels.has(normChannel)) {
      this.channels.set(normChannel, new Set());
    }
    const subscribers = this.channels.get(normChannel)!;

    const isNew = !subscribers.has(sessionId);
    subscribers.add(sessionId);

    if (!this.sessionChannels.has(sessionId)) {
      this.sessionChannels.set(sessionId, new Set());
    }
    this.sessionChannels.get(sessionId)!.add(normChannel);

    if (isNew) {
      channelLogger.debug({ channel: normChannel, sessionId }, 'Session subscribed to channel');
    }
    return isNew;
  }

  /**
   * Unsubscribe a session from a channel.
   * @returns true if the session was actually subscribed
   */
  unlisten(channel: string, sessionId: string): boolean {
    const normChannel = channel.toLowerCase();
    const subscribers = this.channels.get(normChannel);
    if (!subscribers) return false;

    const removed = subscribers.delete(sessionId);
    if (removed) {
      // Clean up empty channel
      if (subscribers.size === 0) {
        this.channels.delete(normChannel);
      }
      // Clean up session channel tracking
      const sessionChans = this.sessionChannels.get(sessionId);
      if (sessionChans) {
        sessionChans.delete(normChannel);
        if (sessionChans.size === 0) {
          this.sessionChannels.delete(sessionId);
        }
      }
      channelLogger.debug({ channel: normChannel, sessionId }, 'Session unsubscribed from channel');
    }
    return removed;
  }

  /**
   * Unsubscribe a session from ALL channels (called on disconnect).
   */
  unlistenAll(sessionId: string): void {
    const sessionChans = this.sessionChannels.get(sessionId);
    if (!sessionChans) return;

    for (const channel of [...sessionChans]) {
      const subscribers = this.channels.get(channel);
      if (subscribers) {
        subscribers.delete(sessionId);
        if (subscribers.size === 0) {
          this.channels.delete(channel);
        }
      }
    }
    this.sessionChannels.delete(sessionId);
    channelLogger.debug({ sessionId }, 'Session unsubscribed from all channels');
  }

  /**
   * Notify all subscribers on a channel.
   * @returns Array of notification events to deliver
   */
  notify(channel: string, payload: string): NotificationEvent[] {
    const normChannel = channel.toLowerCase();
    const subscribers = this.channels.get(normChannel);
    if (!subscribers || subscribers.size === 0) return [];

    // PG notifies even if session hasn't processed prior notifications;
    // we deliver all pending notifications.
    const events: NotificationEvent[] = [];
    for (const sessionId of subscribers) {
      events.push({
        sessionId,
        channel: normChannel,
        payload,
      });
    }

    channelLogger.debug({ channel: normChannel, count: events.length }, 'Notifications generated');
    return events;
  }

  /**
   * Get the list of channels a session is subscribed to.
   */
  getChannels(sessionId: string): string[] {
    const sessionChans = this.sessionChannels.get(sessionId);
    return sessionChans ? [...sessionChans] : [];
  }

  /**
   * Get total number of channels tracked.
   */
  get channelCount(): number {
    return this.channels.size;
  }

  /**
   * Get total number of sessions subscribed to any channel.
   */
  get subscriberCount(): number {
    return this.sessionChannels.size;
  }

  /**
   * Reset all state (for testing).
   */
  clear(): void {
    this.channels.clear();
    this.sessionChannels.clear();
  }
}
