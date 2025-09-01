/**
 * Health check endpoint for Cloudflare Pages Functions
 * @param {Object} context - Pages Functions context
 * @returns {Promise<Response>} Health status response
 */
export async function onRequest(context) {
  const healthData = {
    status: 'ok',
    timestamp: new Date().toISOString(),
    service: 'xget',
    platform: 'cloudflare-pages',
    version: '1.0.0',
    environment: context.env.ENVIRONMENT || 'production',
    uptime: 'unknown'
  };

  const headers = new Headers({
    'Content-Type': 'application/json',
    'Cache-Control': 'no-cache, no-store, must-revalidate',
    Pragma: 'no-cache',
    Expires: '0'
  });

  // Add security headers
  headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  headers.set('X-Frame-Options', 'DENY');
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('X-XSS-Protection', '1; mode=block');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  headers.set(
    'Content-Security-Policy',
    "default-src 'none'; script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none';"
  );

  return new Response(JSON.stringify(healthData, null, 2), {
    status: 200,
    headers
  });
}