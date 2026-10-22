/*
 * SchedProbe FuzzLab - corpus admission scheduler for AFL++.
 *
 * Loaded through AFL_CUSTOM_MUTATOR_LIBRARY (AFL++ tolerates a library that only
 * implements the queue hooks, which is what this one does: it mutates nothing).
 *
 * WHY THIS HOOK AND NOT A MUTATOR
 *
 * The research question is about scheduling, not about mutation. Reimplementing mutation
 * would make every comparison a comparison of two mutators, which is a different (and much
 * less defensible) experiment. AFL++ already owns mutation, execution and coverage; the
 * only thing this library touches is *which queue entry gets fuzzed*, through
 * afl_custom_queue_get(). Same engine, same mutator, same target, same budget - one
 * variable.
 *
 * WHAT IT DECIDES
 *
 * For each candidate queue entry, admit or skip. The score combines two signals that can be
 * enabled independently, because the experiment needs to separate them:
 *
 *   static   - cheap structural features computed from the seed bytes alone (nesting depth,
 *              token variety, size bucket, boundary-character density). It encodes "this
 *              input looks like it exercises several parser states".
 *   feedback - recency and starvation: how recently the entry was added to the queue, and
 *              how many times it has already been fuzzed. It encodes "the fuzzer has been
 *              visiting something else lately", which is what AFL++'s own favoured-entry
 *              logic does not track per entry across cycles.
 *
 * Modes (FUZZLAB_MODE): "all" (baseline A: admit everything), "static", "feedback",
 * "full" (experiment C). Weights come from FUZZLAB_W_STATIC / FUZZLAB_W_FEEDBACK so the
 * same binary serves every arm and the only difference between arms is configuration.
 *
 * DETERMINISM
 *
 * The admission decision must be reproducible from (seed, filename, visit count) alone, or
 * the experiment is not repeatable and the numbers are noise. So the RNG is a splitmix64
 * over exactly those three values - no time, no pid, no address, no global mutable state
 * that depends on scheduling of the fuzzer itself.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "afl_types.h"

#define FUZZLAB_MAX_TRACKED (1u << 16)
#define FUZZLAB_MAX_SIZE 65536u

typedef struct {
  uint64_t hash;
  uint32_t visits;
  uint32_t first_seq;
} entry_state_t;

typedef struct {
  uint32_t next_created;
  uint64_t rng_salt;
  uint32_t open_slots;
  entry_state_t *entries;
  /* configuration */
  int mode; /* 0=all 1=static 2=feedback 3=full */
  double w_static;
  double w_feedback;
  double bias;
  /* counters for the run record */
  uint64_t admitted;
  uint64_t skipped;
  uint64_t decided;
  char log_path[512];
  FILE *log;
} fuzzlab_state_t;

/* ---------------------------------------------------------------- configuration */

static int parse_mode(const char *value) {
  if (value == NULL) return 3;
  if (strcmp(value, "all") == 0) return 0;
  if (strcmp(value, "static") == 0) return 1;
  if (strcmp(value, "feedback") == 0) return 2;
  return 3;
}

static double parse_double(const char *name, double fallback) {
  const char *value = getenv(name);
  if (value == NULL || *value == '\0') return fallback;
  return strtod(value, NULL);
}

/* ---------------------------------------------------------------- hashing */

static uint64_t splitmix64(uint64_t x) {
  x += 0x9e3779b97f4a7c15ULL;
  x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
  x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
  return x ^ (x >> 31);
}

static uint64_t hash_filename(const uint8_t *filename) {
  uint64_t h = 0xcbf29ce484222325ULL; /* FNV-1a */
  for (const uint8_t *p = filename; p != NULL && *p != '\0'; ++p) {
    h ^= (uint64_t)(*p);
    h *= 0x100000001b3ULL;
  }
  return h;
}

/* ---------------------------------------------------------------- static features */

/*
 * Structural score in [0, 1]. Deliberately cheap: this runs for every admission decision,
 * so it must not dominate the fuzzer's own work. The features are JSON-shaped because the
 * target is a JSON parser, and a scheduling signal that ignored the input's structure would
 * be a size filter with extra steps.
 */
static double static_score(const uint8_t *buf, size_t len) {
  if (len == 0) return 0.0;

  uint32_t braces = 0, brackets = 0, quotes = 0, colons = 0, commas = 0;
  uint32_t controls = 0;
  uint8_t seen[256] = {0};
  uint32_t distinct = 0;
  uint32_t depth = 0, max_depth = 0;

  size_t limit = len < FUZZLAB_MAX_SIZE ? len : FUZZLAB_MAX_SIZE;
  for (size_t i = 0; i < limit; ++i) {
    const uint8_t c = buf[i];
    if (!seen[c]) {
      seen[c] = 1;
      ++distinct;
    }
    switch (c) {
      case '{': ++braces; ++depth; if (depth > max_depth) max_depth = depth; break;
      case '[': ++brackets; ++depth; if (depth > max_depth) max_depth = depth; break;
      case '}': case ']': if (depth > 0) --depth; break;
      case '"': ++quotes; break;
      case ':': ++colons; break;
      case ',': ++commas; break;
      default:
        if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') ++controls;
        break;
    }
  }

  const double tokens = (double)(braces + brackets + quotes + colons + commas);
  const double structural = tokens / (double)limit;       /* 0..1, saturates quickly */
  const double variety = (double)distinct / 64.0;         /* 64 distinct bytes is rich */
  const double nesting = (double)max_depth / 16.0;        /* 16 levels is deep */
  const double control_density = (double)controls / (double)limit;
  (void)brackets;

  double score = 0.45 * (structural > 1.0 ? 1.0 : structural) + 0.30 * (variety > 1.0 ? 1.0 : variety) +
                 0.20 * (nesting > 1.0 ? 1.0 : nesting) + 0.05 * (control_density > 1.0 ? 1.0 : control_density);
  if (score < 0.0) score = 0.0;
  if (score > 1.0) score = 1.0;
  return score;
}

/* ---------------------------------------------------------------- feedback features */

/*
 * Feedback score in [0, 1] from two things the hook can actually observe:
 *
 *   novelty  - entries are created by AFL++ only when an input reached new coverage, so a
 *              higher creation sequence means "found later", i.e. further into the
 *              exploration front. Recent frontier entries deserve more of the budget.
 *   fairness - an entry that has already been fuzzed many times without the queue growing
 *              is less interesting than one that has never been tried.
 *
 * `created_total` is the number of queue entries created so far, which the hook learns from
 * afl_custom_queue_new_entry. Percentile-within-queue is a coarse but observable proxy for
 * "how deep into the exploration this seed is".
 */
static double feedback_score(uint32_t first_seq, uint32_t created_total, uint32_t visits) {
  double novelty = 0.0;
  if (created_total > 1) {
    novelty = (double)(first_seq > 0 ? first_seq : 1) / (double)created_total;
    if (novelty > 1.0) novelty = 1.0;
  }
  double fairness = 1.0;
  if (visits > 0) {
    fairness = 1.0 / (1.0 + (double)visits);
  }
  double score = 0.6 * novelty + 0.4 * fairness;
  if (score < 0.0) score = 0.0;
  if (score > 1.0) score = 1.0;
  return score;
}

/* ---------------------------------------------------------------- entry table */

static entry_state_t *find_or_create(fuzzlab_state_t *s, uint64_t hash) {
  if (s->entries == NULL) return NULL;
  const uint32_t mask = (FUZZLAB_MAX_TRACKED - 1u);
  uint32_t slot = (uint32_t)(hash & mask);
  for (uint32_t probe = 0; probe < 64; ++probe) {
    entry_state_t *e = &s->entries[(slot + probe) & mask];
    if (e->hash == hash) return e;
    if (e->hash == 0) {
      e->hash = hash ? hash : 1;
      e->visits = 0;
      e->first_seq = s->next_created++;
      ++s->open_slots;
      return e;
    }
  }
  return NULL; /* table pressure: fall through to "admit", see below */
}

/* ---------------------------------------------------------------- AFL++ hooks */

void *afl_custom_init(afl_state_t *afl, unsigned int seed) {
  (void)afl;
  fuzzlab_state_t *s = (fuzzlab_state_t *)calloc(1, sizeof(fuzzlab_state_t));
  if (s == NULL) return NULL;
  s->entries = (entry_state_t *)calloc(FUZZLAB_MAX_TRACKED, sizeof(entry_state_t));
  if (s->entries == NULL) {
    free(s);
    return NULL;
  }
  s->mode = parse_mode(getenv("FUZZLAB_MODE"));
  s->w_static = parse_double("FUZZLAB_W_STATIC", 1.0);
  s->w_feedback = parse_double("FUZZLAB_W_FEEDBACK", 1.0);
  s->bias = parse_double("FUZZLAB_BIAS", 0.0);
  /* The seed is part of the RNG so that different AFL++ -s values give different sampling;
   * it is the only non-structural input to a decision. */
  /* The creation counter starts at zero. An earlier version seeded it from the fuzzer
   * seed, which made novelty = first_seq/created_total always exceed 1.0 and clamped the
   * feedback signal to a constant - the policy silently degenerated while still looking
   * like it was running. The seed belongs in the sampling RNG, not in the counter. */
  s->next_created = 0;
  s->rng_salt = splitmix64((uint64_t)seed | 0x51ed2702ULL);

  const char *log_path = getenv("FUZZLAB_LOG");
  if (log_path != NULL && *log_path != '\0') {
    snprintf(s->log_path, sizeof(s->log_path), "%s", log_path);
    s->log = fopen(s->log_path, "w");
    if (s->log != NULL) {
      fprintf(s->log, "{\"event\":\"init\",\"mode\":%d,\"w_static\":%.4f,\"w_feedback\":%.4f,\"seed\":%u}\n",
              s->mode, s->w_static, s->w_feedback, seed);
    }
  }
  return s;
}

u32 afl_custom_fuzz_count(void *data, const u8 *buf, size_t buf_size) {
  (void)data;
  (void)buf;
  (void)buf_size;
  return 0; /* this library does not mutate */
}

/*
 * This library does not mutate, and `afl_custom_fuzz_count` returning 0 means AFL++ will
 * never ask it to. The symbol has to exist anyway.
 *
 * That is not a formality - it is the whole reason the first version of this experiment
 * measured nothing. AFL++ loaded the .so, printed
 *     WARNING: Symbol 'afl_custom_fuzz' not found. Try 'afl_custom_mutator'.
 * and then silently never called `afl_custom_queue_get`. Five arms ran 10,000+ executions
 * each and recorded 0 to 2 scheduling decisions, so the "policy" under test was inert and
 * every comparison was really a comparison of the same thing. The warning was in the log
 * the whole time; what made it visible was counting the decisions instead of trusting that
 * a loaded plugin was a working one.
 */
size_t afl_custom_fuzz(void *data, u8 *buf, size_t buf_size, u8 **out_buf,
                       u8 *add_buf, size_t add_buf_size, size_t max_size) {
  (void)data;
  (void)buf;
  (void)buf_size;
  (void)add_buf;
  (void)add_buf_size;
  (void)max_size;
  (void)out_buf;
  return 0; /* never called: fuzz_count is 0 */
}

/*
 * Called when AFL++ adds an entry to the queue. Tracked so that recency is observable; the
 * hook never modifies anything the fuzzer relies on.
 */
void afl_custom_queue_new_entry(void *data, const u8 *filename_new_queue, const u8 *filename_orig_queue) {
  (void)filename_orig_queue;
  fuzzlab_state_t *s = (fuzzlab_state_t *)data;
  if (s == NULL || filename_new_queue == NULL) return;
  find_or_create(s, hash_filename(filename_new_queue));
}

u8 afl_custom_queue_get(void *data, const u8 *filename) {
  fuzzlab_state_t *s = (fuzzlab_state_t *)data;
  if (s == NULL || filename == NULL) return 1;

  const uint64_t hash = hash_filename(filename);
  entry_state_t *entry = find_or_create(s, hash);
  const uint32_t visits = entry != NULL ? entry->visits : 0;
  const uint32_t first_seq = entry != NULL ? entry->first_seq : 0;

  ++s->decided;

  if (s->mode == 0) { /* baseline A: admit everything */
    if (entry != NULL) ++entry->visits;
    ++s->admitted;
    return 1;
  }

  double score = 0.0;
  double weight = 0.0;
  double s_score = 0.0, f_score = 0.0;

  if (s->mode == 1 || s->mode == 3) {
    FILE *f = fopen((const char *)filename, "rb");
    if (f != NULL) {
      static uint8_t buffer[FUZZLAB_MAX_SIZE];
      size_t n = fread(buffer, 1, sizeof(buffer), f);
      fclose(f);
      s_score = static_score(buffer, n);
    }
    score += s->w_static * s_score;
    weight += s->w_static;
  }
  if (s->mode == 2 || s->mode == 3) {
    f_score = feedback_score(first_seq, s->next_created, visits);
    score += s->w_feedback * f_score;
    weight += s->w_feedback;
  }

  if (weight > 0.0) score /= weight;
  score += s->bias;
  if (score < 0.0) score = 0.0;
  if (score > 1.0) score = 1.0;

  /* Deterministic sampling: same seed + same filename + same visit index -> same decision. */
  const uint64_t draw = splitmix64(hash ^ s->rng_salt ^ splitmix64((uint64_t)visits + 1u));
  const double u = (double)(draw >> 11) / (double)(1ULL << 53);
  const u8 admit = (u8)(u < score);

  if (entry != NULL) ++entry->visits;
  if (admit) {
    ++s->admitted;
  } else {
    ++s->skipped;
  }
  if (s->log != NULL) {
    fprintf(s->log,
            "{\"event\":\"decide\",\"hash\":\"%016llx\",\"visits\":%u,\"first\":%u,"
            "\"s\":%.4f,\"f\":%.4f,\"score\":%.4f,\"u\":%.6f,\"admit\":%u}\n",
            (unsigned long long)hash, visits, first_seq, s_score, f_score, score, u, admit);
  }
  return admit;
}

void afl_custom_deinit(void *data) {
  fuzzlab_state_t *s = (fuzzlab_state_t *)data;
  if (s == NULL) return;
  if (s->log != NULL) {
    fprintf(s->log,
            "{\"event\":\"summary\",\"decided\":%llu,\"admitted\":%llu,\"skipped\":%llu}\n",
            (unsigned long long)s->decided, (unsigned long long)s->admitted,
            (unsigned long long)s->skipped);
    fclose(s->log);
  }
  free(s->entries);
  free(s);
}
