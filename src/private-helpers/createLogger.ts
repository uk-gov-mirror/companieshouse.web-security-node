import ApplicationLogger from "@companieshouse/structured-logging-node/lib/ApplicationLogger";
import { createLogger } from "@companieshouse/structured-logging-node";

const APP_NAME = 'web-security-node'

export const logger: ApplicationLogger = createLogger(APP_NAME);
