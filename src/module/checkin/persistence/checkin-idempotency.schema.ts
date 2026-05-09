import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

/**
 * Records an `Idempotency-Key` we've already accepted for a check-in.
 *
 * The mobile outbox (rayuela-mobile, see docs/OFFLINE_SYNC_PLAN.md §8 #1)
 * sends the same key on every retry so a transient network blip does not
 * produce duplicate check-ins server-side.
 *
 * Lifecycle: rows expire 7 days after creation via the TTL index
 * declared at the bottom of this file.
 */
export type CheckinIdempotencyDocument = CheckinIdempotencyTemplate & Document;

@Schema()
export class CheckinIdempotencyTemplate {
  /** UUID v4 minted by the client. Unique. */
  @Prop({ required: true, unique: true, index: true })
  key: string;

  /** Owner of the original submission. Used to detect cross-user collisions. */
  @Prop({ required: true })
  userId: string;

  /**
   * Id of the [Checkin] resource the original POST created.
   * Absent while the first request is still processing (status: pending).
   */
  @Prop()
  checkinId?: string;

  @Prop({ type: Date, default: Date.now })
  createdAt: Date;

  static collectionName() {
    return 'CheckinIdempotency';
  }
}

export const CheckinIdempotencySchema = SchemaFactory.createForClass(
  CheckinIdempotencyTemplate,
);

// 7-day TTL — Mongo will sweep these rows automatically. The window is
// generous enough to cover phones that stay offline for a week.
CheckinIdempotencySchema.index(
  { createdAt: 1 },
  { expireAfterSeconds: 60 * 60 * 24 * 7 },
);
