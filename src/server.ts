import { app } from './app';
import { startGitHubScanJob } from './jobs/github-scan';

async function start() {
  try {
    const port = Number(process.env.PORT) || 3000;
    const host = process.env.HOST || '0.0.0.0';
    
    await app.listen({ port, host });
    app.log.info(`Server listening on http://${host}:${port}`);

    // Start background jobs
    startGitHubScanJob(app);
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
}

start();