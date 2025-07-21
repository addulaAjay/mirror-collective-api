interface AuditLogEntry {
  id: string;
  timestamp: Date;
  type: string;
  userId: string | null;
  ip: string;
  userAgent: string;
  requestId: string;
  details: Record<string, any>;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

interface SecurityEvent {
  type: string;
  userId: string | null;
  ip: string;
  userAgent: string;
  requestId: string;
  details: Record<string, any>;
}

interface AuthEvent {
  type: string;
  userId: string;
  ip: string;
  userAgent: string;
  requestId: string;
  details: Record<string, any>;
}

/**
 * Audit logging service for security events and authentication
 */
export class AuditLogService {
  private logs: AuditLogEntry[] = [];
  private maxLogs = 10000; // Keep last 10k logs in memory
  private cleanupInterval: any;

  constructor() {
    // Clean up old logs every hour
    this.cleanupInterval = setInterval(
      () => {
        this.cleanup();
      },
      60 * 60 * 1000
    );
  }

  /**
   * Generate unique ID for log entry
   */
  private generateId(): string {
    return `log_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Determine severity based on event type
   */
  private determineSeverity(type: string): 'low' | 'medium' | 'high' | 'critical' {
    const criticalEvents = [
      'AUTH_BRUTE_FORCE_DETECTED',
      'AUTH_TOKEN_VERIFICATION_FAILED',
      'UNAUTHORIZED_ADMIN_ACCESS',
      'ACCOUNT_TAKEOVER_ATTEMPT',
    ];

    const highEvents = [
      'AUTH_BLACKLISTED_TOKEN',
      'AUTHORIZATION_FAILED',
      'UNAUTHORIZED_RESOURCE_ACCESS',
      'SUSPICIOUS_LOGIN_PATTERN',
    ];

    const mediumEvents = [
      'AUTH_INVALID_FORMAT',
      'AUTH_MISSING_HEADER',
      'FAILED_LOGIN_ATTEMPT',
      'PASSWORD_RESET_REQUESTED',
    ];

    if (criticalEvents.includes(type)) return 'critical';
    if (highEvents.includes(type)) return 'high';
    if (mediumEvents.includes(type)) return 'medium';
    return 'low';
  }

  /**
   * Log a security event
   */
  async logSecurityEvent(event: SecurityEvent): Promise<void> {
    const logEntry: AuditLogEntry = {
      id: this.generateId(),
      timestamp: new Date(),
      type: event.type,
      userId: event.userId,
      ip: event.ip,
      userAgent: event.userAgent,
      requestId: event.requestId,
      details: event.details,
      severity: this.determineSeverity(event.type),
    };

    this.logs.push(logEntry);

    // Log to console for development/debugging
    if (process.env.NODE_ENV !== 'production') {
      console.log('🔒 Security Event:', {
        type: logEntry.type,
        severity: logEntry.severity,
        userId: logEntry.userId,
        ip: logEntry.ip,
        details: logEntry.details,
      });
    }

    // In production, you would also send to external logging service
    // Example: await this.sendToExternalLogger(logEntry);
  }

  /**
   * Log an authentication event
   */
  async logAuthEvent(event: AuthEvent): Promise<void> {
    const logEntry: AuditLogEntry = {
      id: this.generateId(),
      timestamp: new Date(),
      type: event.type,
      userId: event.userId,
      ip: event.ip,
      userAgent: event.userAgent,
      requestId: event.requestId,
      details: event.details,
      severity: this.determineSeverity(event.type),
    };

    this.logs.push(logEntry);

    // Log successful auth events in development
    if (process.env.NODE_ENV !== 'production' && event.type === 'AUTH_SUCCESS') {
      console.log('✅ Auth Success:', {
        userId: logEntry.userId,
        ip: logEntry.ip,
        path: event.details.path,
      });
    }
  }

  /**
   * Get logs by user ID
   */
  async getLogsByUser(userId: string, limit: number = 100): Promise<AuditLogEntry[]> {
    return this.logs
      .filter((log) => log.userId === userId)
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
      .slice(0, limit);
  }

  /**
   * Get logs by IP address
   */
  async getLogsByIP(ip: string, limit: number = 100): Promise<AuditLogEntry[]> {
    return this.logs
      .filter((log) => log.ip === ip)
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
      .slice(0, limit);
  }

  /**
   * Get logs by type
   */
  async getLogsByType(type: string, limit: number = 100): Promise<AuditLogEntry[]> {
    return this.logs
      .filter((log) => log.type === type)
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
      .slice(0, limit);
  }

  /**
   * Get logs by severity
   */
  async getLogsBySeverity(
    severity: 'low' | 'medium' | 'high' | 'critical',
    limit: number = 100
  ): Promise<AuditLogEntry[]> {
    return this.logs
      .filter((log) => log.severity === severity)
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
      .slice(0, limit);
  }

  /**
   * Get logs within time range
   */
  async getLogsByTimeRange(
    startTime: Date,
    endTime: Date,
    limit: number = 1000
  ): Promise<AuditLogEntry[]> {
    return this.logs
      .filter((log) => log.timestamp >= startTime && log.timestamp <= endTime)
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
      .slice(0, limit);
  }

  /**
   * Get recent failed login attempts for an IP
   */
  async getRecentFailedLogins(
    ip: string,
    timeWindowMinutes: number = 15
  ): Promise<AuditLogEntry[]> {
    const cutoffTime = new Date(Date.now() - timeWindowMinutes * 60 * 1000);

    return this.logs
      .filter(
        (log) =>
          log.ip === ip &&
          (log.type === 'AUTH_TOKEN_VERIFICATION_FAILED' ||
            log.type === 'AUTH_INVALID_CREDENTIALS') &&
          log.timestamp >= cutoffTime
      )
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
  }

  /**
   * Detect suspicious patterns
   */
  async detectSuspiciousActivity(
    userId?: string,
    ip?: string
  ): Promise<{
    suspiciousLogin: boolean;
    bruteForceDetected: boolean;
    tokenAbuse: boolean;
    details: Record<string, any>;
  }> {
    const now = new Date();
    const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
    const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

    let recentLogs = this.logs.filter((log) => log.timestamp >= oneHourAgo);

    if (userId) {
      recentLogs = recentLogs.filter((log) => log.userId === userId);
    }

    if (ip) {
      recentLogs = recentLogs.filter((log) => log.ip === ip);
    }

    const failedLogins = recentLogs.filter(
      (log) => log.type.includes('AUTH') && log.severity === 'high'
    ).length;

    const tokenFailures = recentLogs.filter(
      (log) => log.type === 'AUTH_TOKEN_VERIFICATION_FAILED'
    ).length;

    // Check for multiple failed login attempts from same IP in past day
    const dailyLogs = this.logs.filter((log) => log.timestamp >= oneDayAgo && log.ip === ip);
    const dailyFailures = dailyLogs.filter(
      (log) => log.type.includes('FAILED') || log.severity === 'high'
    ).length;

    return {
      suspiciousLogin: failedLogins >= 5,
      bruteForceDetected: dailyFailures >= 10,
      tokenAbuse: tokenFailures >= 3,
      details: {
        recentFailedLogins: failedLogins,
        recentTokenFailures: tokenFailures,
        dailyFailures,
        timeWindow: '1 hour',
      },
    };
  }

  /**
   * Get audit statistics
   */
  async getAuditStats(): Promise<{
    totalLogs: number;
    logsBySeverity: Record<string, number>;
    logsByType: Record<string, number>;
    recentActivity: {
      lastHour: number;
      last24Hours: number;
    };
  }> {
    const now = new Date();
    const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
    const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

    const logsBySeverity: Record<string, number> = {};
    const logsByType: Record<string, number> = {};

    this.logs.forEach((log) => {
      logsBySeverity[log.severity] = (logsBySeverity[log.severity] || 0) + 1;
      logsByType[log.type] = (logsByType[log.type] || 0) + 1;
    });

    const recentHour = this.logs.filter((log) => log.timestamp >= oneHourAgo).length;
    const recent24Hours = this.logs.filter((log) => log.timestamp >= oneDayAgo).length;

    return {
      totalLogs: this.logs.length,
      logsBySeverity,
      logsByType,
      recentActivity: {
        lastHour: recentHour,
        last24Hours: recent24Hours,
      },
    };
  }

  /**
   * Clean up old logs
   */
  private cleanup(): void {
    if (this.logs.length > this.maxLogs) {
      // Keep only the most recent logs
      this.logs.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
      this.logs = this.logs.slice(0, this.maxLogs);
    }

    // Remove logs older than 30 days
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    this.logs = this.logs.filter((log) => log.timestamp >= thirtyDaysAgo);
  }

  /**
   * Export logs for external analysis
   */
  async exportLogs(format: 'json' | 'csv' = 'json'): Promise<string> {
    if (format === 'csv') {
      const headers = [
        'id',
        'timestamp',
        'type',
        'userId',
        'ip',
        'userAgent',
        'severity',
        'details',
      ];
      const csvRows = [headers.join(',')];

      this.logs.forEach((log) => {
        const row = [
          log.id,
          log.timestamp.toISOString(),
          log.type,
          log.userId || '',
          log.ip,
          `"${log.userAgent}"`,
          log.severity,
          `"${JSON.stringify(log.details)}"`,
        ];
        csvRows.push(row.join(','));
      });

      return csvRows.join('\n');
    }

    return JSON.stringify(this.logs, null, 2);
  }

  /**
   * Clear all logs (for testing purposes)
   */
  async clearLogs(): Promise<void> {
    this.logs = [];
  }

  /**
   * Destroy service and cleanup resources
   */
  destroy(): void {
    clearInterval(this.cleanupInterval);
    this.logs = [];
  }
}
