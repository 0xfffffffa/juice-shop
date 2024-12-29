/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { type Request, type Response, type NextFunction } from 'express'

module.exports = function serveKeyFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!file.includes('/')) {
const allowedFiles = ["key1.txt", "key2.txt"];

if (allowedFiles.includes(file)) {
    res.sendFile(path.resolve('encryptionkeys/', file));
} else {
    // Handle error, for example send status 404 not found
    res.status(404).send('File not found');
}
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
