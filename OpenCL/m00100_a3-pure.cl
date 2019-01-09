/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#define BIT_LIMIT 120

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_sha1.cl"

__kernel void m00100_mxx (KERN_ATTR_VECTOR ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * base
   */

  const u32 pw_len = pws[gid].pw_len & 255;

  u32x w[64] = { 0 };

  for (int i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    sha1_ctx_vector_t ctx;

    sha1_init_vector (&ctx);

    sha1_update_vector (&ctx, w, pw_len);

    sha1_final_vector (&ctx);

    const u32x r0 = ctx.h[DGST_R0];
    const u32x r1 = ctx.h[DGST_R1];
    const u32x r2 = ctx.h[DGST_R2];
    const u32x r3 = ctx.h[DGST_R3];

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

__kernel void m00100_sxx (KERN_ATTR_VECTOR ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[digests_offset].digest_buf[DGST_R0],
    digests_buf[digests_offset].digest_buf[DGST_R1],
    digests_buf[digests_offset].digest_buf[DGST_R2],
    digests_buf[digests_offset].digest_buf[DGST_R3]
  };

  /**
   * base
   */

  const u32 pw_len = pws[gid].pw_len & 255;

  u32x w[64] = { 0 };

  for (int i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    sha1_ctx_vector_t ctx;

    sha1_init_vector (&ctx);

    sha1_update_vector (&ctx, w, pw_len);

    sha1_final_vector (&ctx);

    const u32x r0 = ctx.h[DGST_R0];
    const u32x r1 = ctx.h[DGST_R1];
    const u32x r2 = ctx.h[DGST_R2];
    const u32x r3 = ctx.h[DGST_R3];

    ctx.h[0] = (ctx.h[0] & 0x55555555) + ((ctx.h[0] >>  1) & 0x55555555);
    ctx.h[0] = (ctx.h[0] & 0x33333333) + ((ctx.h[0] >>  2) & 0x33333333);
    ctx.h[0] = (ctx.h[0] & 0x0F0F0F0F) + ((ctx.h[0] >>  4) & 0x0F0F0F0F);
    ctx.h[0] = (ctx.h[0] & 0x00FF00FF) + ((ctx.h[0] >>  8) & 0x00FF00FF);
    ctx.h[0] = (ctx.h[0] & 0x0000FFFF) + ((ctx.h[0] >> 16) & 0x0000FFFF);

    ctx.h[1] = (ctx.h[1] & 0x55555555) + ((ctx.h[1] >>  1) & 0x55555555);
    ctx.h[1] = (ctx.h[1] & 0x33333333) + ((ctx.h[1] >>  2) & 0x33333333);
    ctx.h[1] = (ctx.h[1] & 0x0F0F0F0F) + ((ctx.h[1] >>  4) & 0x0F0F0F0F);
    ctx.h[1] = (ctx.h[1] & 0x00FF00FF) + ((ctx.h[1] >>  8) & 0x00FF00FF);
    ctx.h[1] = (ctx.h[1] & 0x0000FFFF) + ((ctx.h[1] >> 16) & 0x0000FFFF);

    ctx.h[2] = (ctx.h[2] & 0x55555555) + ((ctx.h[2] >>  1) & 0x55555555);
    ctx.h[2] = (ctx.h[2] & 0x33333333) + ((ctx.h[2] >>  2) & 0x33333333);
    ctx.h[2] = (ctx.h[2] & 0x0F0F0F0F) + ((ctx.h[2] >>  4) & 0x0F0F0F0F);
    ctx.h[2] = (ctx.h[2] & 0x00FF00FF) + ((ctx.h[2] >>  8) & 0x00FF00FF);
    ctx.h[2] = (ctx.h[2] & 0x0000FFFF) + ((ctx.h[2] >> 16) & 0x0000FFFF);

    ctx.h[3] = (ctx.h[3] & 0x55555555) + ((ctx.h[3] >>  1) & 0x55555555);
    ctx.h[3] = (ctx.h[3] & 0x33333333) + ((ctx.h[3] >>  2) & 0x33333333);
    ctx.h[3] = (ctx.h[3] & 0x0F0F0F0F) + ((ctx.h[3] >>  4) & 0x0F0F0F0F);
    ctx.h[3] = (ctx.h[3] & 0x00FF00FF) + ((ctx.h[3] >>  8) & 0x00FF00FF);
    ctx.h[3] = (ctx.h[3] & 0x0000FFFF) + ((ctx.h[3] >> 16) & 0x0000FFFF);

    ctx.h[4] = (ctx.h[4] & 0x55555555) + ((ctx.h[4] >>  1) & 0x55555555);
    ctx.h[4] = (ctx.h[4] & 0x33333333) + ((ctx.h[4] >>  2) & 0x33333333);
    ctx.h[4] = (ctx.h[4] & 0x0F0F0F0F) + ((ctx.h[4] >>  4) & 0x0F0F0F0F);
    ctx.h[4] = (ctx.h[4] & 0x00FF00FF) + ((ctx.h[4] >>  8) & 0x00FF00FF);
    ctx.h[4] = (ctx.h[4] & 0x0000FFFF) + ((ctx.h[4] >> 16) & 0x0000FFFF);

    if(ctx.h[4] + ctx.h[3] + ctx.h[2] + ctx.h[1] + ctx.h[0] > BIT_LIMIT)
    {
        const u32 final_hash_pos = digests_offset + 0;

        if (atomic_inc (&hashes_shown[final_hash_pos]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, final_hash_pos, gid, il_pos);
        }
    }

    //COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}
