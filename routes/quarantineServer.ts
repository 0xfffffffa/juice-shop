/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response, type NextFunction } from 'express'

module.exports = function serveQuarantineFiles () {
  return ({ params, query }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!file.includes('/')) {
const securePath = require('path');

let filePath = securePath.join(__dirname, 'ftp', 'quarantine', file);
if (securePath.normalize(filePath).startsWith(securePath.join(__dirname, 'ftp', 'quarantine'))) {
    res.sendFile(filePath);
} else {
    res.status(403).send('Forbidden');
}
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
