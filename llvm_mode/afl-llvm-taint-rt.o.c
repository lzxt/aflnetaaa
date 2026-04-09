/*
   afl-llvm-taint-rt.o.c - Taint tracking runtime for AFL
*/

#include "../config.h"
#include "../types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include <unistd.h>

#ifndef MAP_SIZE
#define MAP_SIZE (1 << 16)
#endif

#ifndef MAX_FILE
#define MAX_FILE (1 * 1024 * 1024)
#endif

#ifndef MAX_CMP_ID
#define MAX_CMP_ID 4096
#endif

/* 16-bit taint tag, value = input_offset + 1 */
typedef u16 taint_tag_t;
#define TAINT_MAX_OFFSET 65534u

/* Taint map: bitmap for each CMP_ID, tracking which input bytes influenced it */
static u8* __afl_taint_map = NULL;
static u32 __afl_taint_map_size = 0;
static u8* __afl_cmp_hit_map = NULL; /* Per-run CMP hit bitmap */

/* Current input buffer and size */
static u8* __afl_input_buf = NULL;
static u32 __afl_input_size = 0;

/* Shadow memory: maps each memory address to its taint tag */
#define SHADOW_MEM_SIZE (256 * 1024 * 1024)  /* 256MB shadow memory */
static taint_tag_t* __afl_shadow_mem = NULL;

/* Initialize shadow memory */
static void __afl_init_shadow_mem(void) {
  if (!__afl_shadow_mem) {
    __afl_shadow_mem = (taint_tag_t*)calloc(SHADOW_MEM_SIZE / sizeof(taint_tag_t), sizeof(taint_tag_t));
  }
}

/* Convert pointer to shadow memory index */
static inline u32 __afl_ptr_to_shadow_idx(void* ptr) {
  u64 addr = (u64)ptr;
  return (u32)(addr % (SHADOW_MEM_SIZE / sizeof(taint_tag_t)));
}

/* Initialize taint map from shared memory */
__attribute__((constructor)) void __afl_taint_init(void) {

  char *id_str = getenv("__AFL_TAINT_MAP_SHM_ID");
  
  if (!id_str) return;
  
  s32 shm_id = atoi(id_str);
  if (shm_id < 0) return;
  
  __afl_taint_map_size = MAX_CMP_ID * (MAX_FILE / 8);
  __afl_taint_map = (u8*)shmat(shm_id, NULL, 0);
  
  if (__afl_taint_map == (void*)-1) {
    __afl_taint_map = NULL;
    __afl_taint_map_size = 0;
  }

  id_str = getenv("__AFL_CMP_HIT_SHM_ID");
  if (id_str) {
    s32 cmp_shm_id = atoi(id_str);
    if (cmp_shm_id >= 0) {
      __afl_cmp_hit_map = (u8*)shmat(cmp_shm_id, NULL, 0);
      if (__afl_cmp_hit_map == (void*)-1) __afl_cmp_hit_map = NULL;
    }
  }

}

/* Set input buffer for taint tracking */
void __afl_set_taint_input(u8* buf, u32 len) {
  __afl_input_buf = buf;
  __afl_input_size = len;
}

/* Mark a byte offset as tainted */
static inline void __afl_mark_taint_offset(u32 cmp_id, u32 offset) {
  
  if (!__afl_taint_map || cmp_id >= MAX_CMP_ID || offset >= MAX_FILE) return;
  
  u32 byte_idx = cmp_id * (MAX_FILE / 8) + (offset / 8);
  u32 bit_idx = offset % 8;
  
  if (byte_idx < __afl_taint_map_size) {
    __afl_taint_map[byte_idx] |= (1 << bit_idx);
  }

}

/* Propagate taint through operations (lightweight) */
taint_tag_t __afl_taint_propagate(taint_tag_t tag1, taint_tag_t tag2) {
  if (tag1) return tag1;
  return tag2;
}

/* Mark input bytes as tainted after recv/read */
void __afl_taint_source(u8* buf, u32 len) {
  __afl_set_taint_input(buf, len);
  
  if (!__afl_shadow_mem) __afl_init_shadow_mem();
  if (!__afl_shadow_mem || !buf) return;
  
  /* 为每个字节分配 16-bit 标签（偏移量+1） */
  for (u32 i = 0; i < len && i < MAX_FILE; i++) {
    if (i > TAINT_MAX_OFFSET) break;
    u32 idx = __afl_ptr_to_shadow_idx(&buf[i]);
    __afl_shadow_mem[idx] = (taint_tag_t)(i + 1);  /* +1 to avoid 0 (untainted) */
  }
}

/* Check taint at CMP and record in map */
void __afl_check_taint(u32 cmp_id, taint_tag_t tag1, taint_tag_t tag2) {
  
  if (!__afl_taint_map || cmp_id >= MAX_CMP_ID) return;

  if (__afl_cmp_hit_map) __afl_cmp_hit_map[cmp_id] = 1;

  taint_tag_t combined = __afl_taint_propagate(tag1, tag2);
  
  /* Record offsets that influenced this CMP */
  if (combined != 0) {
    /* Tag is offset+1, so extract offset */
    if (tag1 > 0 && tag1 <= (TAINT_MAX_OFFSET + 1)) {
      __afl_mark_taint_offset(cmp_id, tag1 - 1);
    }
    if (tag2 > 0 && tag2 <= (TAINT_MAX_OFFSET + 1)) {
      __afl_mark_taint_offset(cmp_id, tag2 - 1);
    }
  }

}

/* Compatibility API used by stage-2 sink trigger path */
void __afl_check_taint_with_tags(u32 cmp_id, taint_tag_t tag1, taint_tag_t tag2) {
  __afl_check_taint(cmp_id, tag1, tag2);
}

/* Load taint tag (called by instrumentation) */
taint_tag_t __afl_taint_load(void* ptr, u32 size) {
  if (!__afl_shadow_mem) __afl_init_shadow_mem();
  if (!__afl_shadow_mem || !ptr) return 0;

  if (!size) size = 1;
  taint_tag_t tag = 0;
  for (u32 i = 0; i < size; i++) {
    u32 idx = __afl_ptr_to_shadow_idx((u8*)ptr + i);
    taint_tag_t cur = __afl_shadow_mem[idx];
    if (cur) {
      tag = cur;
      break;
    }
  }
  return tag;
}

/* Store taint tag (called by instrumentation) */
void __afl_taint_store(void* ptr, u32 size, taint_tag_t tag) {
  if (!__afl_shadow_mem) __afl_init_shadow_mem();
  if (!__afl_shadow_mem || !ptr) return;
  
  /* Store tag for all bytes (simplified) */
  for (u32 i = 0; i < size; i++) {
    u32 idx = __afl_ptr_to_shadow_idx((u8*)ptr + i);
    __afl_shadow_mem[idx] = tag;
  }
}