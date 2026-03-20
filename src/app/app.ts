import { Hono } from "hono";

export const createApp = () => {
  const app = new Hono();

  return app;
};
