# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm run start:dev       # Development with watch mode
npm run build           # Compile TypeScript to dist/
npm run start:prod      # Run compiled app (dist/main)
npm run test            # Jest unit tests
npm run test:watch      # Jest in watch mode
npm run test:cov        # Coverage report
npm run test:e2e        # End-to-end tests
npm run lint            # ESLint with auto-fix
npm run format          # Prettier formatting
```

Run a single test file:
```bash
npx jest src/module/auth/auth.service.spec.ts
```

Start local infrastructure (MongoDB + Garage S3):
```bash
docker-compose up -d
bash ../init-garage.sh   # First time only
```

## Architecture

All API routes are prefixed with `/v1`. Swagger at `/v1/docs`. Port 3000.

### Module structure

Every module under `src/module/` follows a strict 4-layer pattern:

```
controller → service → DAO → schema
```

- **controller**: HTTP entry; delegates all logic to service
- **service**: orchestrates domain logic and calls DAOs
- **DAO**: thin Mongoose wrapper; CRUD only, no business logic
- **schema**: `@Schema` class with `@Prop` decorators; has static `collectionName()`
- **entities/**: rich domain classes with business methods + Builder classes
- **persistence/**: Mappers (entity↔template), DAOs, schemas

**Mapper pattern** — every entity has `toEntity(doc)` and `toTemplate(entity)` static methods to convert between MongoDB documents and domain objects. Never pass raw Mongoose docs to services.

### Auth

JWT via Passport. Login returns `{ access_token }`. Token payload: `{ username, sub, role }`. Expiry: 1 day.

Guards:
- `JwtAuthGuard` — validates JWT signature and expiry
- `RolesGuard` — checks `@Roles()` decorator metadata against `request.user.role`
- Both guards must be applied together for role-restricted routes

Roles: `UserRole.Admin` and `UserRole.Volunteer` (stored in User document and JWT).

Registration flow: user created with `verified: false` → email sent with UUID token → `POST /auth/verify-email` → sets `verified: true`.

### Gamification engine

Located in `src/module/gamification/entities/engine/`. Strategy + Factory pattern — engines are swappable per project config.

**Points engines** (`gamification/`):
- `BasicPointsEngine` — fixed points per rule match
- `ElasticPointsEngine` — weighted points: `w = 1 + a × d` where `a` = contribution ratio, `d` = distance-to-leader normalizer; rewards engaged users who are behind the leader

**Badge engine**: `BasicBadgeEngine` — grants badges when checkin count matches rule threshold

**Leaderboard engines**: `PointsFirstLBEngine` (sort by points), `BadgesFirstLBEngine` (sort by badges count, then points)

`GamificationEngineFactory` instantiates the correct strategy based on project config.

**Recommendation engines** (`recommendation/`): `SimpleRecommendationEngine` and `AdaptiveRecommendationEngine` (rating-based); both implement `IRecommendationEngine`.

### Game lifecycle (`checkin` module)

`Game.play(checkin)` runs the state machine on each checkin:
1. `pointsEngine.reward()` → compute new points
2. Replace old user instance in users list with updated one (stale-copy update, needed before leaderboard build)
3. `badgeEngine.newBadgesFor()` → compute earned badges
4. `leaderboardEngine.build()` → rank all users
5. Returns `GameStatus { newPoints, newBadges, newLeaderboard }`

`GameBuilder` uses a fluent API; `build()` throws if required fields are missing.

`CheckinService.create()` wires everything: fetches project/users/tasks, uploads images, builds `Game`, calls `game.play()`, persists `Checkin` + `Move`, updates user's `GameProfile`.

### Multi-project scoring

Users have a `gameProfiles[]` array — one `GameProfile` per project (`{ projectId, points, badges[], active }`). This isolates scoring across projects. `user.subscribeToProject()` creates a profile; `unsubscribeFromProject()` deactivates it.

### Rule matching

`PointRule` and `BadgeRule` have `match*()` methods. Rules match on `taskType`, `areaId`, and `timeIntervalId`. The value `'Cualquiera'` acts as a wildcard. This enables declarative configuration without custom engine logic.

### GeoJSON areas

Projects store areas as GeoJSON `FeatureCollection`. Rules reference areas by ID in GeoJSON properties. `GeoUtils.isPointInPolygon()` (Turf.js) validates checkin coordinates against polygon boundaries.

### Environment config

`.env.development` or `.env.production` loaded at startup based on `NODE_ENV`. Key vars:

```
DB_CONNECTION          # MongoDB URI
JWT_SECRET
FRONTEND_URL
S3_ENDPOINT, S3_ACCESS_KEY, S3_SECRET_KEY, S3_BUCKET, S3_REGION
K, RECOMMENDATION_LIMIT, MAX_STARS_AMOUNT, NEUTRAL_SCORE   # Gamification tuning
```
