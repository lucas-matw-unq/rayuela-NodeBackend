# Continuous Delivery

This page describes how Rayuela is automatically built and deployed.

## Deployment Strategy
Rayuela uses a **Continuous Delivery (CD)** approach. Every time code is pushed to the `main` or `master` branches (or a specific feature branch for Northflank), the platform is automatically updated.

### 1. Frontend: Vercel
The frontend is hosted on **Vercel** and follows these CD rules:
- **Automatic Builds**: Vercel is connected to the `rayuela-frontend` repository.
- **Production Branch**: Pushes to `main` trigger a production deployment.
- **Preview Deployments**: Pull requests trigger temporary preview environments.
- **Routing**: `vercel.json` ensures that all routes are handled by the Single Page Application (SPA).

**Vercel Configuration Highlights:**
- **Build Command**: `npm run build`
- **Output Directory**: `dist`
- **Framework**: Vue.js / Vite
- **Rewrites**: All non-file requests are routed to `index.html`.

### 2. Backend: Northflank
The backend services (`rayuela-NodeBackend` and `garage`) are hosted on **Northflank**.
- **Service Deployment**: Northflank is connected directly to the GitHub repository.
- **Build Pipeline**: Northflank automatically detects changes, builds the Node.js application, and deploys the new container.
- **Status Monitoring**: The `rayuela-NodeBackend` service is currently configured with **CD Enabled**, ensuring the latest commits are always live.
- **Secrets Management**: Environment variables are managed within Northflank secret groups, keeping them out of the source code.

### 3. CI/CD Validation
We use **GitHub Actions** to validate code quality before deployment:
- **Linting**: Ensures code style consistency (ESLint).
- **Unit Testing**: Runs the test suite (Jest) across multiple Node.js versions (16.x, 18.x).
- **Status**: Deployment only proceeds if the CI pipeline passes.

## Manual Deployments
For scenarios requiring manual intervention (e.g., forced registry updates), the `build-and-push-dockerhub.sh` script can be used to manually push images to Docker Hub, though this is generally bypassed by the Northflank automated pipeline.
