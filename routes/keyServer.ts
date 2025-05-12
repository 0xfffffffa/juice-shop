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
const express = require('express');
const app = express();
const path = require('path');

app.get('/download/:file(*)', (req, res) => {
  let file = req.params.file;
  let fileLocation = path.join('./', 'encryptionkeys', file);
  if (path.normalize(fileLocation).startsWith(path.join(__dirname, './encryptionkeys'))) {
    res.sendFile(fileLocation);
  } else {
    res.status(403).end('Forbidden');
  }
});
const app = express();
const path = require('path');

app.get('/download/:file(*)', (req, res) => {
  let file = req.params.file;
  let fileLocation = path.join('./', 'encryptionkeys', file);
  if (path.normalize(fileLocation).startsWith(path.join(__dirname, './encryptionkeys'))) {
    res.sendFile(fileLocation);
  } else {
    res.status(403).end('Forbidden');
  }
});
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
