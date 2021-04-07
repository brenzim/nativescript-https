"use strict";
//
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
exports.__esModule = true;
exports.request = exports.disableSSLPinning = exports.enableSSLPinning = void 0;
var types_1 = require("tns-core-modules/utils/types");
var peer = {
    enabled: false,
    allowInvalidCertificates: false,
    validatesDomainName: true
};
function enableSSLPinning(options) {
    // console.log('options', options)
    if (!peer.host && !peer.certificate) {
        var certificate = void 0;
        var inputStream = void 0;
        try {
            var file = new java.io.File(options.certificate);
            inputStream = new java.io.FileInputStream(file);
            var x509Certificate = java.security.cert.CertificateFactory.getInstance('X509').generateCertificate(inputStream);
            peer.x509Certificate = x509Certificate;
            certificate = okhttp3.CertificatePinner.pin(x509Certificate);
            inputStream.close();
        }
        catch (error) {
            try {
                if (inputStream) {
                    inputStream.close();
                }
            }
            catch (e) {
            }
            console.error('nativescript-https > enableSSLPinning error', error);
            return;
        }
        peer.host = options.host;
        peer.commonName = options.commonName || options.host;
        peer.certificate = certificate;
        if (options.allowInvalidCertificates == true) {
            peer.allowInvalidCertificates = true;
        }
        if (options.validatesDomainName == false) {
            peer.validatesDomainName = false;
        }
    }
    peer.enabled = true;
    getClient(true);
    console.log('nativescript-https > Enabled SSL pinning');
}
exports.enableSSLPinning = enableSSLPinning;
function disableSSLPinning() {
    peer.enabled = false;
    getClient(true);
    console.log('nativescript-https > Disabled SSL pinning');
}
exports.disableSSLPinning = disableSSLPinning;
console.info('nativescript-https > Disabled SSL pinning by default');
var Client;
function getClient(reload) {
    if (reload === void 0) { reload = false; }
    // if (!Client) {
    // 	Client = new okhttp3.OkHttpClient()
    // }
    // if (Client) {
    // 	Client.connectionPool().evictAll()
    // 	Client = null
    // }
    if (Client && reload == false) {
        return Client;
    }
    var client = new okhttp3.OkHttpClient.Builder();
    if (peer.enabled == true) {
        // console.log('peer', peer)
        if (peer.host || peer.certificate) {
            var spec = okhttp3.ConnectionSpec.MODERN_TLS;
            client.connectionSpecs(java.util.Collections.singletonList(spec));
            var pinner = new okhttp3.CertificatePinner.Builder();
            pinner.add(peer.host, [peer.certificate]);
            client.certificatePinner(pinner.build());
            if (peer.allowInvalidCertificates == false) {
                try {
                    var x509Certificate = peer.x509Certificate;
                    var keyStore = java.security.KeyStore.getInstance(java.security.KeyStore.getDefaultType());
                    keyStore.load(null, null);
                    // keyStore.setCertificateEntry(peer.host, x509Certificate)
                    keyStore.setCertificateEntry('CA', x509Certificate);
                    // let keyManagerFactory = javax.net.ssl.KeyManagerFactory.getInstance(
                    // 	javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm()
                    // )
                    var keyManagerFactory = javax.net.ssl.KeyManagerFactory.getInstance('X509');
                    keyManagerFactory.init(keyStore, null);
                    var keyManagers = keyManagerFactory.getKeyManagers();
                    var trustManagerFactory = javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm());
                    trustManagerFactory.init(keyStore);
                    var sslContext = javax.net.ssl.SSLContext.getInstance('TLS');
                    sslContext.init(keyManagers, trustManagerFactory.getTrustManagers(), new java.security.SecureRandom());
                    client.sslSocketFactory(sslContext.getSocketFactory());
                }
                catch (error) {
                    console.error('nativescript-https > client.allowInvalidCertificates error', error);
                }
            }
            if (peer.validatesDomainName == true) {
                try {
                    client.hostnameVerifier(new javax.net.ssl.HostnameVerifier({
                        verify: function (hostname, session) {
                            var pp = session.getPeerPrincipal().getName();
                            var hv = javax.net.ssl.HttpsURLConnection.getDefaultHostnameVerifier();
                            if (peer.commonName && peer.commonName[0] === '*') {
                                return hv.verify(peer.host, session) && hostname.indexOf(peer.host) > -1 && hostname.indexOf(session.getPeerHost()) > -1 && pp.indexOf(peer.commonName) !== -1;
                            }
                            else {
                                return hv.verify(peer.host, session) && peer.host === hostname && peer.host === session.getPeerHost() && pp.indexOf(peer.host) !== -1;
                            }
                        }
                    }));
                }
                catch (error) {
                    console.error('nativescript-https > client.validatesDomainName error', error);
                }
            }
        }
        else {
            console.warn('nativescript-https > Undefined host or certificate. SSL pinning NOT working!!!');
        }
    }
    client.connectTimeout(60, java.util.concurrent.TimeUnit.SECONDS);
    Client = client.build();
    return Client;
}
// We have to allow networking on the main thread because larger responses will crash the app with an NetworkOnMainThreadException.
// Note that it would be better to offload it to an AsyncTask but that has to run natively to work properly.
// No time for that now, and actually it only concerns the '.string()' call of response.body().string() below.
var strictModeThreadPolicyPermitAll = new android.os.StrictMode.ThreadPolicy.Builder().permitAll().build();
function request(options) {
    return new Promise(function (resolve, reject) {
        try {
            var client = getClient();
            var httpUrl = okhttp3.HttpUrl.parse(options.url);
            var urlBuilder_1 = httpUrl.newBuilder();
            if (options.params) {
                Object.keys(options.params).forEach(function (param) {
                    urlBuilder_1.addQueryParameter(param, options.params[param]);
                });
            }
            var request_1 = new okhttp3.Request.Builder();
            request_1.url(urlBuilder_1.build());
            if (options.headers) {
                Object.keys(options.headers).forEach(function (key) {
                    request_1.addHeader(key, options.headers[key]);
                });
            }
            var methods = {
                'GET': 'get',
                'HEAD': 'head',
                'DELETE': 'delete',
                'POST': 'post',
                'PUT': 'put',
                'PATCH': 'patch'
            };
            if ((['GET', 'HEAD'].indexOf(options.method) != -1)
                ||
                    (options.method == 'DELETE' && !types_1.isDefined(options.body))) {
                request_1[methods[options.method]]();
            }
            else {
                var type = options.headers['Content-Type'] || 'application/json';
                var body = options.body || {};
                try {
                    body = JSON.stringify(body);
                }
                catch (e) {
                }
                request_1[methods[options.method]](okhttp3.RequestBody.create(okhttp3.MediaType.parse(type), body));
            }
            // enable our policy
            android.os.StrictMode.setThreadPolicy(strictModeThreadPolicyPermitAll);
            client.newCall(request_1.build()).enqueue(new okhttp3.Callback({
                onResponse: function (task, response) {
                    // console.log('onResponse')
                    // console.keys('response', response)
                    // console.log('onResponse > response.isSuccessful()', response.isSuccessful())
                    // let body = response.body()//.bytes()
                    // console.keys('body', body)
                    // console.log('body.contentType()', body.contentType())
                    // console.log('body.contentType().toString()', body.contentType().toString())
                    // console.log('body.bytes()', body.bytes())
                    // console.dump('wtf', wtf)
                    // console.log('opts.url', opts.url)
                    // console.log('body.string()', body.string())
                    // let content: any = response.body().string()
                    // console.log('content', content)
                    // try {
                    // 	content = JSON.parse(response.body().string())
                    // } catch (error) {
                    // 	return reject(error)
                    // }
                    try {
                        var content = response.body().string();
                        try {
                            content = JSON.parse(content);
                        }
                        catch (e) {
                            console.log('Error caught ', e);
                        }
                        var statusCode = response.code();
                        var headers = {};
                        // let heads: okhttp3.Headers = response.headers();
                        // let i: number, len: number = heads.size();
                        // for (i = 0; i < len; i++) {
                        //     let key = heads.name(i);
                        //     let value = heads.value(i);
                        //     headers[key] = value
                        // }
                        resolve({ content: content, statusCode: statusCode, headers: headers });
                    }
                    catch (e) {
                        reject('Thew was a problem trying to parse the response');
                    }
                },
                onFailure: function (task, error) {
                    console.log("There was an error!");
                    reject(error);
                }
            }));
        }
        catch (error) {
            reject(error);
        }
    });
}
exports.request = request;
__exportStar(require("./https.common"), exports);
