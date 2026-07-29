const http = require('node:http');
const { spawn } = require('node:child_process');
const path = require('node:path');

const host = '127.0.0.1';
const publicDir = path.join(__dirname, 'public');
const router = path.join(publicDir, 'index.php');
const php = process.env.PHP_BINARY || 'php';
const ports = [8081, 8082];
const workers = new Map();
let shuttingDown = false;

function startWorker(port) {
  const child = spawn(php, [
    '-d', `extension_dir=${process.env.PHP_EXTENSION_DIR || ''}`,
    '-d', 'extension=pdo_mysql',
    '-S', `${host}:${port}`,
    '-t', publicDir,
    router,
  ], {
    cwd: path.dirname(__dirname),
    env: process.env,
    stdio: ['ignore', 'ignore', 'pipe'],
    windowsHide: true,
  });
  child.stderr.on('data', chunk => {
    const line = chunk.toString();
    if (/Fatal|Error|Failed/i.test(line)) process.stderr.write(`[php:${port}] ${line}`);
  });
  child.on('exit', code => {
    if (!shuttingDown && workers.get(port) === child && code !== 0 && code !== null) {
      console.error(`PHP worker ${port} exited with ${code}`);
    }
  });
  workers.set(port, child);
}

function recycleWorker(port) {
  const worker = workers.get(port);
  if (!worker) return;
  console.log(`Recycling PHP report worker ${port}`);
  workers.delete(port);
  worker.once('exit', () => {
    if (!shuttingDown) setTimeout(() => startWorker(port), 50);
  });
  worker.kill();
}

for (const port of ports) {
  startWorker(port);
}

const server = http.createServer((request, response) => {
  const port = request.url.startsWith('/api/v1/agent/') ? ports[0] : ports[1];
  const upstream = http.request({
    hostname: host,
    port,
    path: request.url,
    method: request.method,
    headers: {...request.headers, host: `${host}:${port}`},
    timeout: 30000,
  }, upstreamResponse => {
    response.writeHead(upstreamResponse.statusCode || 502, upstreamResponse.headers);
    if (request.url.includes('/reports/')) {
      upstreamResponse.once('end', () => recycleWorker(port));
    }
    upstreamResponse.pipe(response);
  });
  upstream.on('timeout', () => upstream.destroy(new Error('Upstream timeout')));
  upstream.on('error', error => {
    if (!response.headersSent) {
      response.writeHead(502, {'Content-Type': 'application/json; charset=utf-8'});
    }
    response.end(JSON.stringify({error: `Local PHP worker unavailable: ${error.message}`}));
  });
  request.pipe(upstream);
});

server.listen(8080, host, () => {
  console.log(`Robber dashboard worker pool: http://${host}:8080/`);
});

function shutdown() {
  shuttingDown = true;
  server.close();
  for (const worker of workers.values()) worker.kill();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
