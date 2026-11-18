import type { Request, Response, NextFunction } from 'express';

interface RateBucket {
  timestamps: number[];
}

export function createRateLimiter(options: {
  windowMs: number;
  maxRequests: number;
  keyPrefix?: string;
}) {
  const buckets = new Map<string, RateBucket>();

  return function rateLimitMiddleware(req: Request, res: Response, next: NextFunction): void {
    const now = Date.now();
    const ip =
      (typeof req.headers['x-forwarded-for'] === 'string'
        ? req.headers['x-forwarded-for'].split(',')[0]?.trim()
        : undefined) ||
      req.ip ||
      'unknown';
    const key = `${options.keyPrefix ?? 'global'}:${ip}`;
    const bucket = buckets.get(key) ?? { timestamps: [] };
    bucket.timestamps = bucket.timestamps.filter((ts) => now - ts < options.windowMs);

    res.setHeader('X-RateLimit-Limit', String(options.maxRequests));
    res.setHeader('X-RateLimit-Remaining', String(Math.max(0, options.maxRequests - bucket.timestamps.length)));

    if (bucket.timestamps.length >= options.maxRequests) {
      const oldest = bucket.timestamps[0] ?? now;
      const retryAfterSec = Math.max(1, Math.ceil((options.windowMs - (now - oldest)) / 1000));
      res.setHeader('Retry-After', String(retryAfterSec));
      res.status(429).json({
        error: 'Rate limit exceeded. Please wait before submitting additional requests.',
        retryAfterSeconds: retryAfterSec,
      });
      return;
    }

    bucket.timestamps.push(now);
    buckets.set(key, bucket);

    // Opportunistic cleanup to keep memory bounded
    if (buckets.size > 2000) {
      for (const [k, b] of buckets.entries()) {
        if (b.timestamps.length === 0 || now - b.timestamps[b.timestamps.length - 1] > options.windowMs) {
          buckets.delete(k);
        }
      }
    }

    next();
  };
}
