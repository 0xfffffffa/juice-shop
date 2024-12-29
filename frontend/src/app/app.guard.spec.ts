/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { inject, TestBed } from '@angular/core/testing'
import { AccountingGuard, AdminGuard, DeluxeGuard, LoginGuard } from './app.guard'
import { HttpClientTestingModule } from '@angular/common/http/testing'
import { RouterTestingModule } from '@angular/router/testing'
import { ErrorPageComponent } from './error-page/error-page.component'

describe('LoginGuard', () => {
  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [
        HttpClientTestingModule,
        RouterTestingModule.withRoutes([
          { path: '403', component: ErrorPageComponent }
        ]
        )],
      providers: [LoginGuard]
    })
  })

  it('should be created', inject([LoginGuard], (guard: LoginGuard) => {
    expect(guard).toBeTruthy()
  }))

  it('should open for authenticated users', inject([LoginGuard], (guard: LoginGuard) => {
    localStorage.setItem('token', 'TOKEN')
    expect(guard.canActivate()).toBeTrue()
  }))

  it('should close for anonymous users', inject([LoginGuard], (guard: LoginGuard) => {
    localStorage.removeItem('token')
    expect(guard.canActivate()).toBeFalse()
  }))

  it('returns payload from decoding a valid JWT', inject([LoginGuard], (guard: LoginGuard) => {
The use of `localStorage` for potentially sensitive data like tokens is not secure. Instead, you should use HTTP-only cookies to store tokens.

Cookies with the `HttpOnly` attribute can only be accessed through the HTTP protocol and not by client-side scripts. In this way, even if there is a successful XSS attack, these cookies can't be accessed, thus, the token is secure. However, JavaScript code doesn't provide direct functionality to set `HttpOnly` cookies. It's something that has to be done on the server-side.

Here is an example of setting secure HTTP-only cookies on the server-side using Node.js with express:

```JS
const express = require('express')
const cookieParser = require('cookie-parser')

const app = express()
app.use(cookieParser())

app.get('/setToken', (req, res) => {
  res.cookie('token', 'your.token.here', { httpOnly: true, secure: true })
  res.send('Token set')
})

app.listen(3000)
```

In this code, Express.js is used to create a server and cookie-parser middleware is used to parse cookies. The '/setToken' route sets a cookie named 'token' with the value 'your.token.here'. The options `{ httpOnly: true, secure: true }` ensure that the cookie is not accessible through JavaScript and is only sent over HTTPS.
    expect(guard.tokenDecode()).toEqual({
      sub: '1234567890',
      name: 'John Doe',
      iat: 1516239022
    })
  }))

  it('returns nothing when decoding an invalid JWT', inject([LoginGuard], (guard: LoginGuard) => {
    localStorage.setItem('token', '12345.abcde')
    expect(guard.tokenDecode()).toBeNull()
  }))

  it('returns nothing when decoding an non-existing JWT', inject([LoginGuard], (guard: LoginGuard) => {
    localStorage.removeItem('token')
    expect(guard.tokenDecode()).toBeNull()
  }))
})

describe('AdminGuard', () => {
  let loginGuard: any

  beforeEach(() => {
    loginGuard = jasmine.createSpyObj('LoginGuard', ['tokenDecode', 'forbidRoute'])

    TestBed.configureTestingModule({
      imports: [
        HttpClientTestingModule,
        RouterTestingModule.withRoutes([
          { path: '403', component: ErrorPageComponent }
        ]
        )],
      providers: [
        AdminGuard,
        { provide: LoginGuard, useValue: loginGuard }
      ]
    })
  })

  it('should be created', inject([AdminGuard], (guard: AdminGuard) => {
    expect(guard).toBeTruthy()
  }))

  it('should open for admins', inject([AdminGuard], (guard: AdminGuard) => {
    loginGuard.tokenDecode.and.returnValue({ data: { role: 'admin' } })
    expect(guard.canActivate()).toBeTrue()
  }))

  it('should close for regular customers', inject([AdminGuard], (guard: AdminGuard) => {
    loginGuard.tokenDecode.and.returnValue({ data: { role: 'customer' } })
    expect(guard.canActivate()).toBeFalse()
    expect(loginGuard.forbidRoute).toHaveBeenCalled()
  }))

  it('should close for deluxe customers', inject([AdminGuard], (guard: AdminGuard) => {
    loginGuard.tokenDecode.and.returnValue({ data: { role: 'deluxe' } })
    expect(guard.canActivate()).toBeFalse()
    expect(loginGuard.forbidRoute).toHaveBeenCalled()
  }))

  it('should close for accountants', inject([AdminGuard], (guard: AdminGuard) => {
    loginGuard.tokenDecode.and.returnValue({ data: { role: 'accounting' } })
    expect(guard.canActivate()).toBeFalse()
    expect(loginGuard.forbidRoute).toHaveBeenCalled()
  }))
})

describe('AccountingGuard', () => {
  let loginGuard: any

  beforeEach(() => {
    loginGuard = jasmine.createSpyObj('LoginGuard', ['tokenDecode', 'forbidRoute'])

    TestBed.configureTestingModule({
      imports: [
        HttpClientTestingModule,
        RouterTestingModule.withRoutes([
          { path: '403', component: ErrorPageComponent }
        ]
        )],
      providers: [
        AccountingGuard,
        { provide: LoginGuard, useValue: loginGuard }
      ]
    })
  })

  it('should be created', inject([AccountingGuard], (guard: AccountingGuard) => {
    expect(guard).toBeTruthy()
  }))

  it('should open for accountants', inject([AccountingGuard], (guard: AccountingGuard) => {
    loginGuard.tokenDecode.and.returnValue({ data: { role: 'accounting' } })
    expect(guard.canActivate()).toBeTrue()
  }))

  it('should close for regular customers', inject([AccountingGuard], (guard: AccountingGuard) => {
    loginGuard.tokenDecode.and.returnValue({ data: { role: 'customer' } })
    expect(guard.canActivate()).toBeFalse()
    expect(loginGuard.forbidRoute).toHaveBeenCalled()
  }))

  it('should close for deluxe customers', inject([AccountingGuard], (guard: AccountingGuard) => {
    loginGuard.tokenDecode.and.returnValue({ data: { role: 'deluxe' } })
    expect(guard.canActivate()).toBeFalse()
    expect(loginGuard.forbidRoute).toHaveBeenCalled()
  }))

  it('should close for admins', inject([AccountingGuard], (guard: AccountingGuard) => {
    loginGuard.tokenDecode.and.returnValue({ data: { role: 'admin' } })
    expect(guard.canActivate()).toBeFalse()
    expect(loginGuard.forbidRoute).toHaveBeenCalled()
  }))
})

describe('DeluxeGuard', () => {
  let loginGuard: any

  beforeEach(() => {
    loginGuard = jasmine.createSpyObj('LoginGuard', ['tokenDecode'])

    TestBed.configureTestingModule({
      imports: [
        HttpClientTestingModule,
        RouterTestingModule.withRoutes([
          { path: '403', component: ErrorPageComponent }
        ]
        )],
      providers: [
        DeluxeGuard,
        { provide: LoginGuard, useValue: loginGuard }
      ]
    })
  })

  it('should be created', inject([DeluxeGuard], (guard: DeluxeGuard) => {
    expect(guard).toBeTruthy()
  }))

  it('should open for deluxe customers', inject([DeluxeGuard], (guard: DeluxeGuard) => {
    loginGuard.tokenDecode.and.returnValue({ data: { role: 'deluxe' } })
    expect(guard.isDeluxe()).toBeTrue()
  }))

  it('should close for regular customers', inject([DeluxeGuard], (guard: DeluxeGuard) => {
    loginGuard.tokenDecode.and.returnValue({ data: { role: 'customer' } })
    expect(guard.isDeluxe()).toBeFalse()
  }))

  it('should close for admins', inject([DeluxeGuard], (guard: DeluxeGuard) => {
    loginGuard.tokenDecode.and.returnValue({ data: { role: 'admin' } })
    expect(guard.isDeluxe()).toBeFalse()
  }))

  it('should close for accountants', inject([DeluxeGuard], (guard: DeluxeGuard) => {
    loginGuard.tokenDecode.and.returnValue({ data: { role: 'accounting' } })
    expect(guard.isDeluxe()).toBeFalse()
  }))
})
