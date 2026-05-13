# Offline Sync Architecture

This document summarizes the architecture and implementation of the **Offline Sync** feature introduced in `rayuela-mobile` PR #1 and `rayuela-NodeBackend` PR #42.

## 1. Fundamental Concepts

The system follows **Local-First** principles. Instead of the app failing when the network is absent, it treats the device's storage as the "source of truth" for pending actions.

*   **Outbox Pattern:** Actions (check-ins) are serialized into a queue (SQLite) immediately. Sending to the server happens asynchronously.
*   **Idempotency:** Every check-in is assigned a UUID `Idempotency-Key`. This ensures that if a sync is interrupted and retried, the server doesn't create duplicate check-ins.
*   **Stale-While-Revalidate:** For reading data (projects/tasks), the app shows the cached version from SQLite first, then updates it if a network connection is available.

## 2. Key Libraries Involved

| Category | Libraries |
| :--- | :--- |
| **Data & Sync** | `sqflite`, `connectivity_plus`, `workmanager`, `uuid` |
| **Media & Maps** | `flutter_cache_manager`, `latlong2` |

## 3. Architectural Patterns

### The Outbox Pattern

The **Outbox Pattern** ensures reliable data synchronization. Instead of sending data directly to an API and failing if the network is down, the application saves the data and the *intent to send* in a single local atomic operation.

```mermaid
graph TD
    A[User Action] --> B[Local Transaction]
    subgraph SQLite Device Storage
        B --> C[(Domain Data)]
        B --> D[(Outbox Table)]
    end
    D --> E[Background Drainer]
    E -- retry with backoff --> F[Remote Backend API]
    F -- 200 OK --> G[Delete Outbox Entry]
    G --> D
```

**Benefits:**
*   **Guaranteed Delivery:** Data remains in the Outbox until the server confirms receipt.
*   **UI Responsiveness:** User sees "Success" instantly due to fast local save.
*   **Offline Resilience:** Identical logic regardless of connectivity state.

### The "Outbox" Flow in Rayuela

1.  **Persistence:** Images saved to filesystem via `ImageStore`; metadata to SQLite via `OutboxDao`.
2.  **Reactive Trigger:** `OutboxLifecycle` detects new entries or "online" events and calls `OutboxService.drain()`.
3.  **Strategic Retry:** `JitteredExponentialBackoff` handles server downtime (e.g., 5s, 1m, 30m).

## 4. Offline Tiles Handling

The map subsystem supports persistent tile storage and proactive prefetching using **Slippy Map** math.

### UML: Offline Map Subsystem

```mermaid
classDiagram
    direction TB
    TilePrefetcher --> TileCoord : generates
    TileCoord --> TileLayer : identified by
    TileLayer --> CacheManager : retrieves from
    
    class TileCoord {
        +int x
        +int y
        +int z
        +urlFrom(template)
    }
    class TilePrefetcher {
        +prefetch(projectId)
        +cancel(projectId)
    }
    class CacheManager {
        +getFile(url)
        +putFile(url, bytes)
    }
```

### Visual Rendering Bridge

The visual map component (`flutter_map`) connects to caching via a custom `CachedTileProvider`.

```mermaid
flowchart LR
    Map[flutter_map Widget] --> Layer[TileLayer]
    Layer -- Needs Tile (x,y,z) --> Provider[CachedTileProvider]
    Provider -- getImage() --> Img[_CachedTileImage]
    Img -- Load Bytes --> CacheSvc[TileCacheService]
    CacheSvc -- Hit --> Disk[(Local FileSystem)]
    CacheSvc -- Miss --> OSM[OpenStreetMap Servers]
```

### Tile Caching Lifecycle

```mermaid
sequenceDiagram
    participant Map as FlutterMap Layer
    participant Cache as CacheManager (LRU)
    participant OSM as OpenStreetMap API

    rect rgb(240, 240, 240)
    note over Map, OSM: Path 1: On-Demand (Real-time Browsing)
    Map->>Cache: Request Tile (z,x,y)
    alt In Cache
        Cache-->>Map: Return image file
    else Not in Cache
        Cache->>OSM: Download Tile
        OSM-->>Cache: 200 OK (PNG)
        Cache->>Cache: Save to disk (LRU)
        Cache-->>Map: Return image file
    end
    end

    rect rgb(230, 245, 255)
    note over Map, OSM: Path 2: Prefetching (Bulk Download)
    User->>Map: Click "Download Area"
    Map->>Cache: Fetch all Tiles for Box(z12-16)
    loop for each TileCoord
        Cache->>OSM: Download Tile
        OSM-->>Cache: 200 OK
        Cache->>Cache: Persist (Infinite TTL*)
    end
    note right of Cache: *Pre-cached tiles are marked to avoid LRU eviction
    end
```

## 5. Background Sync Strategy

*   **Foreground:** Triggered by `ConnectivityService` and `AppLifecycleState.resumed`.
*   **Background:** `WorkManager` (Android) and `BGTaskScheduler` (iOS) wake up the app approximately every **1 hour** to attempt a drain.

## 6. Sequence Diagrams

### Flow A: Opening the Check-in View (Data Fetching)

```mermaid
sequenceDiagram
    participant UI as Check-in Screen
    participant Repo as Data Repository
    participant Cache as SQLite Cache
    participant API as Backend API

    UI->>Repo: Request Projects/Tasks
    Repo->>Cache: Read local data
    Cache-->>Repo: Return cached data (if any)
    Repo-->>UI: Yield data (fast path)

    alt is Online
        Repo->>API: Fetch latest data
        API-->>Repo: Return fresh data
        Repo->>Cache: Update local cache
        Repo-->>UI: Yield updated data
    else is Offline
        Repo->>API: Fetch latest data
        API--xRepo: Network Error
        note right of Repo: Silently handled, UI keeps showing cached data
    end
```

### Flow B: Check-in Submission (The Outbox Flow)

```mermaid
sequenceDiagram
    participant UI as Check-in Screen
    participant Outbox as OutboxService
    participant DB as SQLite (OutboxDao)
    participant Net as ConnectivityService
    participant API as Backend API

    UI->>Outbox: enqueue(checkin_data, images)
    Outbox->>DB: Save images & metadata (status: pending)
    DB-->>Outbox: entry created
    UI-->>UI: Show "Pending" or "Success" based on immediate state

    Outbox->>Outbox: trigger drain()
    Outbox->>Net: check isOnline()

    alt is Offline
        Net-->>Outbox: returns false
        note right of Outbox: Drain aborts. Will retry when connection returns or via Background Job.
    else is Online
        Net-->>Outbox: returns true
        Outbox->>DB: nextEligible()
        DB-->>Outbox: returns pending entry
        Outbox->>API: POST /checkin (with Idempotency-Key)
        
        alt API Success
            API-->>Outbox: 200 OK / 409 Conflict
            Outbox->>DB: delete(entry)
        else API Retryable Error
            API--xOutbox: 503 / Timeout
            Outbox->>DB: markFailed(entry, nextAttemptAt)
            note right of Outbox: Backoff strategy determines next attempt
        end
    end
```

## 7. Backend Supporting Changes (PR #42)

The backend is **Idempotent-Aware**, ensuring that mobile retries do not corrupt data or double-count points.

### The Idempotency Lifecycle

```mermaid
sequenceDiagram
    participant Mobile
    participant API as CheckinController
    participant Idem as IdempotencyDao
    participant DB as MongoDB

    Mobile->>API: POST /checkin (Header: Idempotency-Key)
    API->>Idem: findByKey(UUID)
    
    alt Key Exists (Retry)
        Idem-->>API: Returns CheckinId
        API->>DB: findOne(CheckinId)
        DB-->>API: Original Record
        API-->>Mobile: 200 OK (Header: X-Original-Resource)
    else Key New (First Time)
        API->>API: Process Gamification
        API->>DB: Create Checkin
        API->>Idem: record(UUID, userId, CheckinId)
        API-->>Mobile: 200 OK
    end
```

### Key Considerations

*   **TTL Eviction:** Idempotency keys expire after **7 days** via MongoDB TTL index.
*   **Active Probing:** New `/health` endpoint for mobile reachability detection.
*   **Error Classification:** `MulterExceptionFilter` maps file errors to 4xx codes to guide outbox retry behavior.
