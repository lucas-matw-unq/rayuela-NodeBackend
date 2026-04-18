# Deployment: Stage Environment

This page describes the architecture and deployment process for the Rayuela stage environment.

## Architecture Diagram

```mermaid
flowchart TB
    Browser["🌐 Browser"]

    subgraph Vercel["☁️ Vercel (Frontend)"]
        VFE["rayuela-frontend\nStatic Site (SPA)"]
    end

    subgraph Atlas["🍃 MongoDB Atlas (Free Tier)"]
        DB[("free-mongo-cluster\n.5pdg0du.mongodb.net/rayuela")]
    end

    subgraph Northflank["🚀 Northflank — Proyecto: rayuela (us-central)"]
        subgraph ns["Namespace: ns-9v9rbv2pxhtx"]
            BE["rayuela-NodeBackend\nNode.js :3000\np01--rayuela-nodebackend--9v9rbv2pxhtx.code.run\n[PUBLIC]"]
            GR["garage\ndxflrs/garage:v2.2.0 :3900\np01--garage--9v9rbv2pxhtx.code.run\n[INTERNAL]"]
        end
    end

    subgraph GitHub["🐙 GitHub (lucas-matw-unq)"]
        REPO_BE["rayuela-NodeBackend\nbranch: feat/northflank-deployment"]
        REPO_FE["rayuela-frontend"]
    end

    Browser -->|"HTTPS"| VFE
    VFE -->|"VITE_ROOT_API\nhttps://.../v1"| BE
    BE -->|"mongodb+srv://"| DB
    BE -->|"http://garage:3900\nS3 API"| GR

    REPO_BE -->|"CI build → deploy"| BE
    REPO_FE -->|"CI deploy"| VFE
```

## Overview
Rayuela uses a distributed cloud architecture:
- **Frontend**: Hosted on Vercel as a Vue.js SPA.
- **Backend**: NestJS application running on Northflank.
- **Database**: Managed MongoDB Atlas cluster.
- **Storage**: Garage (S3-compatible) running alongside the backend in Northflank.

## Environment Variables
The backend service (`rayuela-NodeBackend`) requires the following configuration:

| Variable | Description | Value (Stage) |
|----------|-------------|---------------|
| `DB_CONNECTION` | MongoDB connection string | `mongodb+srv://...` |
| `JWT_SECRET` | Secret key for JWT signing | `fda6c62...` |
| `S3_ENDPOINT` | Garage S3 API endpoint | `http://garage:3900` |
| `S3_ACCESS_KEY` | Garage Access Key | `GKeb4b3...` |
| `S3_SECRET_KEY` | Garage Secret Key | `65cbf33...` |
| `S3_BUCKET` | S3 bucket for check-ins | `rayuela-checkins` |
| `S3_REGION` | S3 region identifier | `garage` |
| `NOREPLY_EMAIL` | Email for notifications | `unqarq2@gmail.com` |
| `FRONTEND_URL` | Production Frontend URL | `https://rayuela-frontend-nine.vercel.app` |
| `NODE_ENV` | Environment mode | `production` |
