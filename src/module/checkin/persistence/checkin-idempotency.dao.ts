import { ConflictException, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import {
  CheckinIdempotencyDocument,
  CheckinIdempotencyTemplate,
} from './checkin-idempotency.schema';

export interface IdempotencyHit {
  key: string;
  userId: string;
  checkinId?: string;
}

@Injectable()
export class CheckinIdempotencyDao {
  constructor(
    @InjectModel(CheckinIdempotencyTemplate.collectionName())
    private readonly model: Model<CheckinIdempotencyDocument>,
  ) {}

  /**
   * Atomically claim an idempotency key before the create pipeline runs.
   *
   * Uses `findOneAndUpdate` with `upsert: true` so the unique index on
   * `key` acts as the real gate — only one concurrent request can insert
   * the row; all others see the existing document.
   *
   * Returns:
   *   - `null`                        → caller won the race; proceed with create.
   *   - `{ checkinId: string }`       → key already processed; caller should replay.
   *   - `{ checkinId: undefined }`    → another request is still processing; caller
   *                                     should return 409 and tell client to retry.
   *
   * Throws ConflictException when the key belongs to a different userId.
   */
  async claimKey(key: string, userId: string): Promise<IdempotencyHit | null> {
    const existing = await this.model
      .findOneAndUpdate(
        { key },
        { $setOnInsert: { key, userId, createdAt: new Date() } },
        { upsert: true, new: false },
      )
      .lean<IdempotencyHit>()
      .exec();

    if (!existing) return null; // won the race

    if (existing.userId !== userId) {
      throw new ConflictException(
        'Idempotency-Key already used by another account',
      );
    }

    return {
      key: existing.key,
      userId: existing.userId,
      checkinId: existing.checkinId,
    };
  }

  /**
   * Finalize the idempotency record after the check-in has been created.
   * Called once the create pipeline completes successfully.
   */
  async setCheckinId(key: string, checkinId: string): Promise<void> {
    await this.model.updateOne({ key }, { $set: { checkinId } }).exec();
  }
}
