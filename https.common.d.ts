// 

import {HttpRequestOptions, Headers} from 'http'


export interface HttpsSSLPinningOptions {
    host: string
    certificate: string
    allowInvalidCertificates?: boolean
    validatesDomainName?: boolean
    commonName?: string
}

export interface HttpsRequestObject {
    [key: string]: string | number
}

export interface HttpsRequestOptions {
    url: string
    method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD'
    headers?: Headers
    params?: HttpsRequestObject
    body?: any
}

export interface HttpsResponse {
    headers?: Headers
    statusCode?: number
    content?: any
    reason?: string
    reject?: boolean
}












