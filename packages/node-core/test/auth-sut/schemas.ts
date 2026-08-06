/**
 * Request schemas for admin login / TOTP confirm.
 *
 * Relocated off frozen apps/node. Strict Zod — unexpected
 * keys reject. MIN_PASSWORD_LENGTH shared with node-core bootstrap floor.
 */
import { z } from "zod";

import { MIN_PASSWORD_LENGTH } from "../../src/http/admin-bootstrap.js";

export const loginSchema = z
  .object({
    username: z.string().min(1).max(256),
    password: z.string().min(1).max(1024),
    totp: z.string().max(16).optional(),
  })
  .strict();

export type LoginInput = z.infer<typeof loginSchema>;

export const enrolTotpSchema = z
  .object({
    password: z.string().min(1).max(1024),
  })
  .strict();

export type EnrolTotpInput = z.infer<typeof enrolTotpSchema>;

export const confirmTotpSchema = z
  .object({
    totp: z.string().regex(/^\d{6}$/, "totp must be 6 digits"),
  })
  .strict();

export type ConfirmTotpInput = z.infer<typeof confirmTotpSchema>;

export const changePasswordSchema = z
  .object({
    current_password: z.string().min(1).max(1024),
    new_password: z.string().min(MIN_PASSWORD_LENGTH).max(1024),
  })
  .strict();

export type ChangePasswordInput = z.infer<typeof changePasswordSchema>;
