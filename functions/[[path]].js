import { CONFIG, createConfig } from '../src/config/index.js';
import { transformPath } from '../src/config/platforms.js';

/**
 * Monitors performance metrics during request processing
 */
class PerformanceMonitor {
  /**
   * Initializes a new performance monitor
   */
  constructor() {
    this.startTime = Date.now();
    this.marks = new Map();
  }

  /**
   * Marks a timing point with the given name
   * @param {string} name - The name of the timing mark
   */
  mark(name) {
    if (this.marks.has(name)) {
      console.warn(`Mark with name ${name} already exists.`);
    }
    this.marks.set(name, Date.now() - this.startTime);
  }

  /**
   * Returns all collected metrics
   * @returns {Object.<string, number>} Object containing name-timestamp pairs
   */
  getMetrics() {
    return Object.fromEntries(this.marks.entries());
  }
}

/**
 * Detects if a request is a container registry operation
 * @param {Request} request - The incoming request object
 * @param {URL} url - Parsed URL object
 * @returns {boolean} True if this is a container registry operation
 */
function isDockerRequest(request, url) {
  // Check for container registry API endpoints
  if (url.pathname.startsWith('/v2/')) {
    return true;
  }

  // Check for Docker-specific User-Agent
  const userAgent = request.headers.get('User-Agent') || '';
  if (userAgent.toLowerCase().includes('docker/')) {
    return true;
  }

  // Check for Docker-specific Accept headers
  const accept = request.headers.get('Accept') || '';
  if (
    accept.includes('application/vnd.docker.distribution.manifest') ||
    accept.includes('application/vnd.oci.image.manifest') ||
    accept.includes('application/vnd.docker.image.rootfs.diff.tar.gzip')
  ) {
    return true;
  }

  return false;
}

/**
 * Detects if a request is a Git operation
 * @param {Request} request - The incoming request object
 * @param {URL} url - Parsed URL object
 * @returns {boolean} True if this is a Git operation
 */
function isGitRequest(request, url) {
  // Check for Git-specific endpoints
  if (url.pathname.endsWith('/info/refs')) {
    return true;
  }

  if (url.pathname.endsWith('/git-upload-pack') || url.pathname.endsWith('/git-receive-pack')) {
    return true;
  }

  // Check for Git user agents (more comprehensive check)
  const userAgent = request.headers.get('User-Agent') || '';
  if (userAgent.includes('git/') || userAgent.startsWith('git/')) {
    return true;
  }

  // Check for Git-specific query parameters
  if (url.searchParams.has('service')) {
    const service = url.searchParams.get('service');
    return service === 'git-upload-pack' || service === 'git-receive-pack';
  }

  // Check for Git-specific content types
  const contentType = request.headers.get('Content-Type') || '';
  if (contentType.includes('git-upload-pack') || contentType.includes('git-receive-pack')) {
    return true;
  }

  return false;
}

/**
 * Check if the request is for an AI inference provider
 * @param {Request} request - The incoming request object
 * @param {URL} url - Parsed URL object
 * @returns {boolean} True if this is an AI inference request
 */
function isAIInferenceRequest(request, url) {
  // Check for AI inference provider paths (ip/{provider}/...)
  if (url.pathname.startsWith('/ip/')) {
    return true;
  }

  // Check for common AI inference API endpoints
  const aiEndpoints = [
    '/v1/chat/completions',
    '/v1/completions',
    '/v1/messages',
    '/v1/predictions',
    '/v1/generate',
    '/v1/embeddings',
    '/openai/v1/chat/completions'
  ];

  if (aiEndpoints.some(endpoint => url.pathname.includes(endpoint))) {
    return true;
  }

  // Check for AI-specific content types
  const contentType = request.headers.get('Content-Type') || '';
  if (contentType.includes('application/json') && request.method === 'POST') {
    // Additional check for common AI inference patterns in URL
    if (
      url.pathname.includes('/chat/') ||
      url.pathname.includes('/completions') ||
      url.pathname.includes('/generate') ||
      url.pathname.includes('/predict')
    ) {
      return true;
    }
  }

  return false;
}

/**
 * Validates incoming requests against security rules
 * @param {Request} request - The incoming request object
 * @param {URL} url - Parsed URL object
 * @param {import('../src/config/index.js').ApplicationConfig} config - Configuration object
 * @returns {{valid: boolean, error?: string, status?: number}} Validation result
 */
function validateRequest(request, url, config = CONFIG) {
  // Allow POST method for Git, Docker, and AI inference operations
  const isGit = isGitRequest(request, url);
  const isDocker = isDockerRequest(request, url);
  const isAI = isAIInferenceRequest(request, url);

  const allowedMethods =
    isGit || isDocker || isAI
      ? ['GET', 'HEAD', 'POST', 'PUT', 'PATCH']
      : config.SECURITY.ALLOWED_METHODS;

  if (!allowedMethods.includes(request.method)) {
    return { valid: false, error: 'Method not allowed', status: 405 };
  }

  if (url.pathname.length > config.SECURITY.MAX_PATH_LENGTH) {
    return { valid: false, error: 'Path too long', status: 414 };
  }

  return { valid: true };
}

/**
 * Creates a standardized error response
 * @param {string} message - Error message
 * @param {number} status - HTTP status code
 * @param {boolean} includeDetails - Whether to include detailed error information
 * @returns {Response} Error response
 */
function createErrorResponse(message, status, includeDetails = false) {
  const errorBody = includeDetails
    ? JSON.stringify({ error: message, status, timestamp: new Date().toISOString() })
    : message;

  return new Response(errorBody, {
    status,
    headers: addSecurityHeaders(
      new Headers({
        'Content-Type': includeDetails ? 'application/json' : 'text/plain'
      })
    )
  });
}

/**
 * Adds security headers to the response
 * @param {Headers} headers - The headers object to modify
 * @returns {Headers} Modified headers with security headers added
 */
function addSecurityHeaders(headers) {
  headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  headers.set('X-Frame-Options', 'DENY');
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('X-XSS-Protection', '1; mode=block');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  headers.set(
    'Content-Security-Policy',
    "default-src 'none'; script-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none';"
  );
  return headers;
}

/**
 * Creates an abbreviated health check response for non-/health paths
 * @returns {Response} Health check response
 */
function createHealthResponse() {
  const healthData = {
    status: 'ok',
    timestamp: new Date().toISOString(),
    service: 'xget'
  };

  return new Response(JSON.stringify(healthData), {
    status: 200,
    headers: addSecurityHeaders(
      new Headers({
        'Content-Type': 'application/json',
        'Cache-Control': 'no-cache, no-store, must-revalidate'
      })
    )
  });
}

/**
 * Main request handler
 * @param {Request} request - The incoming request
 * @param {Object} env - Environment variables
 * @param {ExecutionContext} ctx - Execution context
 * @returns {Promise<Response>} The response object
 */
export async function handleRequest(request, env, ctx) {
  const monitor = new PerformanceMonitor();
  monitor.mark('start');

  try {
    // Create configuration with environment variables
    const config = createConfig(env);
    const url = new URL(request.url);

    // Handle health check endpoint
    if (url.pathname === '/health' || url.pathname === '/api/health') {
      return createHealthResponse();
    }

    // Validate request
    const validation = validateRequest(request, url, config);
    if (!validation.valid) {
      return createErrorResponse(validation.error, validation.status);
    }

    monitor.mark('validation');

    // Check if it's a special operation type
    const isGit = isGitRequest(request, url);
    const isDocker = isDockerRequest(request, url);
    const isAI = isAIInferenceRequest(request, url);

    // Transform URL path to target URL
    const targetUrl = transformPath(url.pathname, url.search, config.PLATFORMS);
    if (!targetUrl) {
      return createErrorResponse('Invalid or unsupported platform URL', 400);
    }

    monitor.mark('transform');

    // Create cache key for non-special operations
    const cache = caches.default;
    const cacheKey = new Request(request.url, { method: 'GET' });

    // Try cache first for regular requests (not Git, Docker, or AI operations)
    if (!isGit && !isDocker && !isAI && ['GET', 'HEAD'].includes(request.method)) {
      const cachedResponse = await cache.match(cacheKey);
      if (cachedResponse) {
        monitor.mark('cache-hit');
        return addPerformanceHeaders(cachedResponse, monitor);
      }
    }

    monitor.mark('cache-miss');

    // Create headers for the upstream request
    const headers = new Headers();

    // Copy relevant headers from the original request
    const headersToCopy = [
      'Accept',
      'Accept-Encoding',
      'Accept-Language',
      'Authorization',
      'Cache-Control',
      'Content-Type',
      'User-Agent',
      'Range',
      'If-Range',
      'If-Modified-Since',
      'If-None-Match'
    ];

    for (const headerName of headersToCopy) {
      const value = request.headers.get(headerName);
      if (value) {
        headers.set(headerName, value);
      }
    }

    // For Git and Docker operations, copy additional headers
    if (isGit || isDocker) {
      const additionalHeaders = [
        'Docker-Content-Digest',
        'Docker-Distribution-API-Version',
        'WWW-Authenticate',
        'X-Docker-Token'
      ];

      for (const headerName of additionalHeaders) {
        const value = request.headers.get(headerName);
        if (value) {
          headers.set(headerName, value);
        }
      }
    }

    // Set default User-Agent if not present
    if (!headers.has('User-Agent')) {
      headers.set('User-Agent', 'Xget/1.0 (+https://github.com/howsen82/xget)');
    }

    monitor.mark('headers');

    // Create request options
    const requestOptions = {
      method: request.method,
      headers,
      signal: AbortSignal.timeout(config.TIMEOUT_SECONDS * 1000)
    };

    // Add body for non-GET/HEAD requests
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      requestOptions.body = request.body;
    }

    // Retry logic
    let response;
    let lastError;

    for (let attempt = 0; attempt <= config.MAX_RETRIES; attempt++) {
      try {
        response = await fetch(targetUrl, requestOptions);
        break;
      } catch (error) {
        lastError = error;
        if (attempt < config.MAX_RETRIES) {
          await new Promise(resolve => setTimeout(resolve, config.RETRY_DELAY_MS * (attempt + 1)));
        }
      }
    }

    if (!response) {
      throw lastError || new Error('Failed to fetch after retries');
    }

    monitor.mark('fetch');

    // Process response headers
    const responseHeaders = new Headers();

    // Copy relevant headers from the response
    const responseHeadersToCopy = [
      'Content-Type',
      'Content-Length',
      'Content-Range',
      'Accept-Ranges',
      'Content-Encoding',
      'Content-Disposition',
      'ETag',
      'Last-Modified',
      'Cache-Control',
      'Expires'
    ];

    for (const headerName of responseHeadersToCopy) {
      const value = response.headers.get(headerName);
      if (value) {
        responseHeaders.set(headerName, value);
      }
    }

    // For Git and Docker operations, copy additional response headers
    if (isGit || isDocker) {
      const additionalResponseHeaders = [
        'Docker-Content-Digest',
        'Docker-Distribution-API-Version',
        'WWW-Authenticate',
        'X-Docker-Token',
        'Location'
      ];

      for (const headerName of additionalResponseHeaders) {
        const value = response.headers.get(headerName);
        if (value) {
          responseHeaders.set(headerName, value);
        }
      }
    }

    // Add CORS headers if needed
    if (
      config.SECURITY.ALLOWED_ORIGINS.includes('*') ||
      config.SECURITY.ALLOWED_ORIGINS.includes(request.headers.get('Origin'))
    ) {
      responseHeaders.set('Access-Control-Allow-Origin', request.headers.get('Origin') || '*');
      responseHeaders.set('Access-Control-Allow-Methods', 'GET, HEAD, POST, PUT, PATCH, OPTIONS');
      responseHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, Range');
      responseHeaders.set(
        'Access-Control-Expose-Headers',
        'Content-Range, Accept-Ranges, Content-Length'
      );
    }

    // Set cache control for successful responses
    if (response.ok && !isGit && !isDocker && !isAI) {
      responseHeaders.set('Cache-Control', `public, max-age=${config.CACHE_DURATION}`);
    }

    // Add security headers
    addSecurityHeaders(responseHeaders);

    monitor.mark('response-headers');

    // Stream the response body
    let responseBody;
    if (response.body) {
      responseBody = response.body;
    } else {
      responseBody = null;
    }

    // Create final response
    const finalResponse = new Response(responseBody, {
      status: response.status,
      headers: responseHeaders
    });

    // Cache successful responses (skip caching for Git, Docker, and AI inference operations)
    // Only cache GET and HEAD requests to avoid "Cannot cache response to non-GET request" errors
    if (
      !isGit &&
      !isDocker &&
      !isAI &&
      ['GET', 'HEAD'].includes(request.method) &&
      (response.ok || response.status === 206)
    ) {
      ctx.waitUntil(cache.put(cacheKey, finalResponse.clone()));
    }

    monitor.mark('complete');
    return isGit || isDocker || isAI
      ? finalResponse
      : addPerformanceHeaders(finalResponse, monitor);
  } catch (error) {
    console.error('Error handling request:', error);
    const message = error instanceof Error ? error.message : String(error);
    return createErrorResponse(`Internal Server Error: ${message}`, 500, true);
  }
}

/**
 * Adds performance metrics to response headers
 * @param {Response} response - The response object
 * @param {PerformanceMonitor} monitor - Performance monitor instance
 * @returns {Response} New response with performance headers
 */
function addPerformanceHeaders(response, monitor) {
  const headers = new Headers(response.headers);
  headers.set('X-Performance-Metrics', JSON.stringify(monitor.getMetrics()));
  addSecurityHeaders(headers);
  return new Response(response.body, {
    status: response.status,
    headers
  });
}

/**
 * Cloudflare Pages Functions export
 * @param {Object} context - Pages Functions context
 * @returns {Promise<Response>} The response object
 */
export async function onRequest(context) {
  return handleRequest(context.request, context.env, context);
}