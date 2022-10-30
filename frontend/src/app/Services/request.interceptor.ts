/*
 * Copyright (c) 2014-2022 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { HttpEvent, HttpHandler, HttpInterceptor, HttpRequest, HttpXsrfTokenExtractor } from '@angular/common/http'
import { Injectable } from '@angular/core'
import { Observable } from 'rxjs'

// Token name set by angular HttpClientXsrfModule
const HEADER_NAME = 'X-XSRF-TOKEN'

@Injectable()
export class RequestInterceptor implements HttpInterceptor {
  constructor(private readonly tokenExtractor: HttpXsrfTokenExtractor) {
  }

  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    // if request is a data mutating operation
    // set the XSRF Header
    if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
      const token = this.tokenExtractor.getToken()

      if (token !== null && !req.headers.has(HEADER_NAME)) {
        req = req.clone({ headers: req.headers.set(HEADER_NAME, token) })
      }
    }

    if (localStorage.getItem('token')) {
      req = req.clone({
        setHeaders: {
          Authorization: `Bearer ${localStorage.getItem('token')}`
        }
      })
    }
    if (localStorage.getItem('email')) {
      req = req.clone({
        setHeaders: {
          'X-User-Email': String(localStorage.getItem('email'))
        }
      })
    }
    return next.handle(req)
  }
}
