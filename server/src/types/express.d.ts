import * as express from 'express';

declare global {
  namespace Express {
    interface Request {
      actor?: any; // Use your specific Actor type here if you have one
    }
  }
}