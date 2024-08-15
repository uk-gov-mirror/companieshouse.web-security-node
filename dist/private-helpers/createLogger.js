"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.logger = void 0;
const structured_logging_node_1 = require("@companieshouse/structured-logging-node");
const APP_NAME = 'web-security-node';
exports.logger = (0, structured_logging_node_1.createLogger)(APP_NAME);
