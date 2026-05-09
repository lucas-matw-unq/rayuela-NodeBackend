import { ConflictException, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import {
  CheckinIdempotencyDocument,
  CheckinIdempotencyTemplate,
} from './checkin-idempotency.schema';

/** What [findByKey] returns. */
export interface IdempotencyHit {
  key: string;
  userId: string;
  checkinId: string;
}

@Injectable()
export class CheckinIdempotencyDao {
  constructor(
    @InjectModel(CheckinIdempotencyTemplate.collectionName())
    private readonly model: Model<CheckinIdempotencyDocument>,
  ) {}

  /**
   * Look up a previously-recorded idempotency key.
   *
   * Returns `null` when the key is unknown — the controller should then
   * proceed with the normal create path. Returns the stored row when
   * the key matches; the service decides whether the userId fits.
   */
  async findByKey(key: string): Promise<IdempotencyHit | null> {
    const row = await this.model.findOne({ key }).lean<IdempotencyHit>().exec();
    if (!row) return null;
    return { key: row.key, userId: row.userId, checkinId: row.checkinId };
  }

  /**
   * Persist a new (key, user, checkin) triplet. Throws if `key` is
   * already present — the caller is expected to have called
   * [findByKey] first, so a clash here is a real race.
   */
  async record(params: {
    key: string;
    userId: string;
    checkinId: string;
  }): Promise<void> {
    try {
      await this.model.create({
        key: params.key,
        userId: params.userId,
        checkinId: params.checkinId,
        createdAt: new Date(),
      });
    } catch (err: any) {
      // E11000 duplicate key — another request inserted first. Caller's
      // intent is "remember this", so a best-effort retry is fine.
      if (err?.code === 11000) {
        const existing = await this.findByKey(params.key);
        if (existing && existing.userId === params.userId) {
          return; // someone beat us to it with the same user — fine.
        }
        throw new ConflictException(
          'Idempotency-Key already used by another account',
        );
      }
      throw err;
    }
  }
}
