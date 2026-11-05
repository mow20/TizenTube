"use strict";

const fs = require('fs');
const http = require('http');
const ogHttps = require('https');
const https = require('./https.js');
const net = require('net');
const tls = require('tls');
const forge = require('node-forge');
const url = require('url');
const fetch = require('node-fetch');
const userScriptUrl = require('./userScriptUrl.js');

const proxyPort = 8101;

// The userscript is kept here (and on disk, so it survives a service restart)
// and written inline into /tv. Loading it with <script src> meant a CDN
// download on every page load: right after the TV wakes up that download often
// failed or came in after YouTube had started, leaving TizenTube missing or
// half applied. Every /tv load refreshes the copy in the background, so
// updates arrive by the next load.
const userScriptCachePath = '/home/owner/share/tizentube-userscript.js';
let userScript = null;
try {
    userScript = fs.readFileSync(userScriptCachePath, 'utf8') || null;
} catch (e) { }

let userScriptRequest = null;
function refreshUserScript() {
    if (userScriptRequest) return;
    // Without a timeout, a request that hangs (right after the TV wakes up)
    // would block every later refresh.
    userScriptRequest = fetch(userScriptUrl, { timeout: 30000 }).then(res => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.text();
    }).then(text => {
        if (!text) return;
        userScript = text;
        fs.writeFileSync(userScriptCachePath + '.tmp', text);
        fs.renameSync(userScriptCachePath + '.tmp', userScriptCachePath);
    }).catch(() => { }).then(() => {
        userScriptRequest = null;
    });
}

function userScriptTag() {
    // Only on the very first run, before any copy was downloaded.
    if (!userScript) return `<script src="${userScriptUrl}?ver=${Date.now()}"></script>`;
    // "</script" would end the inline element early.
    return `<script>${userScript.replace(/<\/script/gi, '<\\/script')}</script>`;
}

function startServer() {
    refreshUserScript();

    const caCertificate = forge.pki.certificateFromPem(
        fs.readFileSync('/home/owner/share/tizentube-ca.crt', 'utf8')
    );

    const caPrivateKey = forge.pki.privateKeyFromPem(
        fs.readFileSync('/home/owner/share/tizentube-ca.key', 'utf8')
    );

    function createHostCertificate(hostname) {
        const keys = forge.pki.rsa.generateKeyPair(2048);
        const certificate = forge.pki.createCertificate();

        certificate.publicKey = keys.publicKey;
        certificate.serialNumber = Date.now().toString(16);
        certificate.validity.notBefore = new Date();
        certificate.validity.notAfter = new Date();
        certificate.validity.notAfter = new Date(
            certificate.validity.notBefore.getTime() + 397 * 24 * 60 * 60 * 1000
        );

        certificate.setSubject([{ name: 'commonName', value: hostname }]);
        certificate.setIssuer(caCertificate.subject.attributes);
        certificate.setExtensions([
            { name: 'basicConstraints', cA: false, critical: true },
            {
                name: 'keyUsage',
                digitalSignature: true,
                keyEncipherment: true,
                critical: true
            },
            { name: 'extKeyUsage', serverAuth: true },
            {
                name: 'subjectAltName',
                altNames: [{ type: 2, value: hostname }]
            },
            { name: 'subjectKeyIdentifier' },
            {
                name: 'authorityKeyIdentifier',
                keyIdentifier: caCertificate.generateSubjectKeyIdentifier().getBytes()
            }
        ]);

        certificate.sign(caPrivateKey, forge.md.sha256.create());

        return {
            key: forge.pki.privateKeyToPem(keys.privateKey),
            cert: forge.pki.certificateToPem(certificate) + forge.pki.certificateToPem(caCertificate)
        };
    }

    function tunnel(hostname, port, clientSocket, initialData) {
        const targetSocket = net.connect(port, hostname, () => {
            clientSocket.write(
                'HTTP/1.1 200 Connection Established\r\n\r\n'
            );

            if (initialData.length) {
                targetSocket.write(initialData);
            }

            clientSocket.pipe(targetSocket);
            targetSocket.pipe(clientSocket);
        });

        targetSocket.on('error', () => clientSocket.destroy());
        clientSocket.on('error', () => targetSocket.destroy());
    }

    // Generating an RSA key in pure JS takes seconds on the TV, and the proxy
    // only listens once both certificates exist. Keep them on disk so a
    // service restart (e.g. after the TV was idle) is ready right away.
    const hostCertCachePath = '/home/owner/share/tizentube-host-certs.json';
    let hostCerts = {};
    try {
        hostCerts = JSON.parse(fs.readFileSync(hostCertCachePath, 'utf8')) || {};
    } catch (e) { }

    function getHostCertificate(hostname) {
        const cached = hostCerts[hostname];
        if (cached) {
            try {
                const certificate = forge.pki.certificateFromPem(cached.cert);
                // Throws if this CA did not sign it (e.g. the CA was recreated).
                if (caCertificate.verify(certificate) &&
                    certificate.validity.notAfter.getTime() > Date.now() + 30 * 24 * 60 * 60 * 1000) {
                    return cached;
                }
            } catch (e) { }
        }

        const created = createHostCertificate(hostname);
        hostCerts[hostname] = created;
        try {
            fs.writeFileSync(hostCertCachePath + '.tmp', JSON.stringify(hostCerts));
            fs.renameSync(hostCertCachePath + '.tmp', hostCertCachePath);
        } catch (e) { }
        return created;
    }

    const ytCertWWW = getHostCertificate('www.youtube.com');
    const ytCert = getHostCertificate('youtube.com');

    function mitm(hostname, port, clientSocket, initialData) {
        clientSocket.write(
            'HTTP/1.1 200 Connection Established\r\n\r\n'
        );

        const tlsServer = new tls.Server(
            hostname === 'www.youtube.com' ? ytCertWWW : ytCert
        );

        tlsServer.on('secureConnection', clientTlsSocket => {
            const httpServer = http.createServer(
                (request, response) => {
                    const pathname = request.url.split('?')[0];
                    const isTvPath = pathname === '/tv' || pathname === '/tv/';

                    const reqHeaders = Object.assign({}, request.headers);

                    if (isTvPath) {
                        reqHeaders['accept-encoding'] = 'identity';
                        // Always get the full page: a 304 or a partial
                        // response has no HTML to put the userscript in.
                        delete reqHeaders['if-none-match'];
                        delete reqHeaders['if-modified-since'];
                        delete reqHeaders['range'];
                        delete reqHeaders['if-range'];
                    }

                    const httpsModule = parseInt(process.version.split('.')[0].replace('v', '')) >= 13 ? ogHttps : https;

                    const targetRequest = httpsModule.request({
                        hostname,
                        port,
                        method: request.method,
                        path: request.url,
                        headers: reqHeaders,
                        servername: hostname,
                        rejectUnauthorized: true,
                        maxHeaderSize: 1024 * 1024
                    }, targetResponse => {
                        const headers = Object.assign({}, targetResponse.headers);

                        const isHtml = /text\/html/i.test(headers['content-type'] || '');

                        if (!isTvPath || !isHtml) {
                            response.writeHead(
                                targetResponse.statusCode,
                                headers
                            );

                            return targetResponse.pipe(response);
                        }

                        delete headers['content-security-policy'];
                        delete headers['content-security-policy-report-only'];
                        headers['content-security-policy'] = [
                            "default-src * data: blob: 'unsafe-inline' 'unsafe-eval'",
                            'img-src * https://dearrow-thumb.ajay.app data: blob:',
                            'media-src * data: blob:',
                            "script-src * https://cdn.jsdelivr.net https://sponsor.ajay.app data: blob: 'unsafe-inline' 'unsafe-eval'",
                            "style-src * data: blob: 'unsafe-inline'",
                            'connect-src * https://cdn.jsdelivr.net https://sponsor.ajay.app https://dearrow-thumb.ajay.app',
                            'font-src * data:'
                        ].join('; ');

                        const chunks = [];
                        let finished = false;

                        // If YouTube's response breaks off, fail the page
                        // load instead of leaving Cobalt waiting forever.
                        const abort = () => {
                            if (finished) return;
                            finished = true;
                            response.destroy();
                        };
                        targetResponse.on('error', abort);
                        targetResponse.on('aborted', abort);

                        targetResponse.on('data', chunk => chunks.push(chunk));

                        targetResponse.on('end', () => {
                            if (finished) return;
                            finished = true;

                            let body = Buffer.concat(chunks).toString('utf8');

                            delete headers['content-length'];
                            delete headers['transfer-encoding'];
                            delete headers['content-encoding'];
                            delete headers['connection'];
                            // Never let Cobalt reuse a cached copy of this
                            // page: only a fresh one gets the current script.
                            delete headers['etag'];
                            delete headers['last-modified'];
                            delete headers['expires'];
                            headers['cache-control'] = 'no-store';

                            body = body.replace(
                                /<meta\b[^>]*http-equiv\s*=\s*["']Content-Security-Policy(?:-Report-Only)?["'][^>]*>/gi,
                                ''
                            );

                            // A function, so "$&" and the like in the script are not
                            // read as replacement patterns.
                            const scriptTag = userScriptTag();
                            if (body.indexOf('</body>') !== -1) {
                                body = body.replace('</body>', () => scriptTag + '</body>');
                            } else {
                                body += scriptTag;
                            }
                            refreshUserScript();

                            headers['content-length'] = Buffer.byteLength(body, 'utf8');
                            headers['connection'] = 'close';
                            headers['content-encoding'] = 'identity';

                            response.writeHead(
                                targetResponse.statusCode,
                                headers
                            );

                            response.end(body);
                        });
                    });

                    targetRequest.on('error', error => {
                        response.destroy();
                    });

                    request.pipe(targetRequest);
                }
            );

            httpServer.emit('connection', clientTlsSocket);
        });

        tlsServer.on('tlsClientError', () => {
            clientSocket.destroy();
        });

        if (initialData && initialData.length) {
            clientSocket.unshift(initialData);
        }

        tlsServer.emit('connection', clientSocket);
    }

    const proxyServer = http.createServer((request, response) => {
        const targetUrl = url.parse(request.url);

        const targetRequest = http.request({
            hostname: targetUrl.hostname,
            port: targetUrl.port || 80,
            method: request.method,
            path: targetUrl.pathname + targetUrl.search,
            headers: request.headers
        }, targetResponse => {
            response.writeHead(
                targetResponse.statusCode,
                targetResponse.headers
            );

            targetResponse.pipe(response);
        });

        targetRequest.on('error', () => response.destroy());
        request.pipe(targetRequest);
    });

    proxyServer.on('connect', (request, clientSocket, initialData) => {
        const reqUrl = request.url.split(':');
        const hostname = reqUrl[0];
        const port = reqUrl[1] || 443;

        // Only these two hosts serve /tv, and only they have a certificate
        // here: intercepting other *.youtube.com hosts would fail TLS.
        if (hostname !== 'youtube.com' && hostname !== 'www.youtube.com') {
            return tunnel(
                hostname,
                Number(port),
                clientSocket,
                initialData
            );
        }

        mitm(
            hostname,
            Number(port),
            clientSocket,
            initialData
        );
    });

    // E.g. the port still held by the previous instance after a restart.
    proxyServer.on('error', () => {
        setTimeout(() => proxyServer.listen(proxyPort, '0.0.0.0'), 1000);
    });

    proxyServer.listen(proxyPort, '0.0.0.0');
}

module.exports = startServer;