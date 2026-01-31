import pino from 'pino';
import pretty from 'pino-pretty';
import { env } from '../config/env';

export const loggerPlugin = env.NODE_ENV === 'development'
  ? pino({
      level: env.LOG_LEVEL,
      transport: {
        target: 'pino-pretty',
        options: {
          colorize: true,
          translateTime: 'HH:MM:ss Z',
          ignore: 'pid,hostname',
        },
      },
    })
  : pino({
      level: env.LOG_LEVEL,
      base: {
        pid: process.pid,
        hostname: undefined,
      },
    });