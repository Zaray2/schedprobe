/*
 * FuzzLab scheduling loop.
 *
 * WHY THIS EXISTS
 *
 * The previous attempt used AFL++'s `afl_custom_queue_get` hook as the scheduling
 * intervention point. That hook is called once per queue entry per queue cycle, and AFL++
 * spends nearly all of a short campaign inside havoc on a single entry: measured, the hook
 * fired 0-2 times per 10,000 executions. No policy can be tested at 1 decision per campaign.
 * libFuzzer has no scheduling hook at all, and its `LLVMFuzzerMutate` cannot be called
 * standalone because it depends on libFuzzer's internal driver state.
 *
 * So the loop is written here, and it is deliberately the *smallest* thing that can host a
 * scheduler:
 *
 *   coverage instrumentation  clang -fsanitize=fuzzer-no-link  (SanitizerCoverage, external)
 *   crash detection           ASAN, in a forked child            (external)
 *   mutation                  standard havoc operators            (not the research variable)
 *   seed scheduling           THE RESEARCH VARIABLE, below
 *
 * Nothing here tries to be a fuzzing engine. Mutation is the textbook havoc set because it
 * only needs to be *constant* across arms for the comparison to mean anything; making it
 * clever would confound the measurement. What is being tested is which seed gets mutated next.
 *
 * Scheduling is the only thing that differs between arms, and all arms share one binary - the
 * policy is chosen at start-up, so the mutation code, the coverage code and the target are
 * byte-identical across conditions.
 *
 * POLICIES
 *
 *   fifo      always mutate the oldest seed. The degenerate baseline: one seed gets all the
 *             budget until it finds something, which is a real strategy and a bad one.
 *   rr        round-robin over the corpus. The honest simple baseline A.
 *   static    highest structural score first (see static_score). No execution feedback.
 *   feedback  recency + starvation only. No static analysis.
 *   full      experiment C: static structure combined with queue feedback.
 *
 * `fifo` and `rr` are the baselines the research question is about; `static` and `feedback`
 * exist so a win can be attributed rather than merely observed.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* ---------------------------------------------------------------- limits */

#define MAX_INPUT 65536u
#define MAX_CORPUS 4096u
#define MAX_CRASHES 256u
#define MAX_COUNTERS (1u << 20)

/* ---------------------------------------------------------------- coverage */

/* Filled in by clang's SanitizerCoverage before main() runs. */
static uint8_t *g_counters = NULL;
static size_t g_counter_count = 0;

void __sanitizer_cov_8bit_counters_init(uint8_t *start, uint8_t *stop) {
  g_counters = start;
  g_counter_count = (size_t)(stop - start);
}

/* One byte per counter: whether it has ever been non-zero. */
static uint8_t *g_seen = NULL;
static uint64_t g_edges_seen = 0;
/* Set by run_one when a counter became non-zero for the first time. */
static int g_new_edges = 0;

/* ---------------------------------------------------------------- rng */

static uint64_t g_rng = 0x9e3779b97f4a7c15ULL;

static uint64_t rnd(void) {
  g_rng += 0x9e3779b97f4a7c15ULL;
  uint64_t z = g_rng;
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
  return z ^ (z >> 31);
}

static size_t rnd_below(size_t n) { return n == 0 ? 0 : (size_t)(rnd() % n); }

/* ---------------------------------------------------------------- corpus */

typedef struct {
  uint8_t *data;
  size_t size;
  uint32_t visits;
  uint32_t created_seq;
  double static_score;
} Seed;

static Seed *g_corpus = NULL;
static size_t g_corpus_len = 0;
static size_t g_created_total = 0;
static uint64_t g_execs = 0;
static uint64_t g_execs_since_new = 0;

/* ---------------------------------------------------------------- static feature */

/*
 * Structural score in [0,1], from bytes only. Same four features and weights as the AFL++
 * plugin used, so the comparison between the two harnesses is about the harness, not the
 * feature definition.
 */
static double static_score(const uint8_t *buf, size_t len) {
  if (len == 0) return 0.0;
  size_t braces = 0, brackets = 0, quotes = 0, colons = 0, commas = 0, controls = 0;
  unsigned seen[256] = {0};
  size_t distinct = 0, depth = 0, max_depth = 0;
  size_t limit = len < 4096u ? len : 4096u;
  for (size_t i = 0; i < limit; ++i) {
    unsigned char c = buf[i];
    if (!seen[c]) { seen[c] = 1; ++distinct; }
    switch (c) {
      case '{': ++braces; if (++depth > max_depth) max_depth = depth; break;
      case '[': ++brackets; if (++depth > max_depth) max_depth = depth; break;
      case '}': case ']': if (depth) --depth; break;
      case '"': ++quotes; break;
      case ':': ++colons; break;
      case ',': ++commas; break;
      default: if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') ++controls; break;
    }
  }
  double tokens = (double)(braces + brackets + quotes + colons + commas);
  double structural = tokens / (double)limit;
  double variety = (double)distinct / 64.0;
  double nesting = (double)max_depth / 16.0;
  double ctrl = (double)controls / (double)limit;
  double score = 0.45 * (structural > 1 ? 1 : structural) + 0.30 * (variety > 1 ? 1 : variety) +
                 0.20 * (nesting > 1 ? 1 : nesting) + 0.05 * (ctrl > 1 ? 1 : ctrl);
  if (score < 0) score = 0;
  if (score > 1) score = 1;
  return score;
}

/* ---------------------------------------------------------------- policies */

typedef enum { P_FIFO = 0, P_RR, P_STATIC, P_FEEDBACK, P_FULL } Policy;

static const char *policy_name(Policy p) {
  switch (p) {
    case P_FIFO: return "fifo";
    case P_RR: return "rr";
    case P_STATIC: return "static";
    case P_FEEDBACK: return "feedback";
    default: return "full";
  }
}

static Policy parse_policy(const char *s) {
  if (!s) return P_RR;
  if (!strcmp(s, "fifo")) return P_FIFO;
  if (!strcmp(s, "rr")) return P_RR;
  if (!strcmp(s, "static")) return P_STATIC;
  if (!strcmp(s, "feedback")) return P_FEEDBACK;
  return P_FULL;
}

static size_t g_rr_cursor = 0;

/*
 * Pick the next seed. Returns an index into g_corpus.
 *
 * Every policy is deterministic given (corpus state, rng), and the rng is seeded from the
 * command line, so a campaign can be replayed exactly.
 */
static size_t pick_seed(Policy policy) {
  if (g_corpus_len == 1) return 0;
  switch (policy) {
    case P_FIFO:
      /* Oldest first, always. Deliberately starves the rest. */
      return 0;
    case P_RR:
      g_rr_cursor = (g_rr_cursor + 1) % g_corpus_len;
      return g_rr_cursor;
    case P_STATIC: {
      size_t best = 0;
      double best_score = -1.0;
      for (size_t i = 0; i < g_corpus_len; ++i) {
        double s = g_corpus[i].static_score;
        if (s > best_score) { best_score = s; best = i; }
      }
      return best;
    }
    case P_FEEDBACK: {
      /*
       * Weighted random over recency and fairness - the same two signals the plugin used.
       * Novelty: created later = closer to the exploration front. Fairness: 1/(1+visits).
       */
      double total = 0.0;
      double *weights = (double *)alloca(sizeof(double) * g_corpus_len);
      for (size_t i = 0; i < g_corpus_len; ++i) {
        double novelty = g_created_total > 1
                             ? (double)(g_corpus[i].created_seq + 1) / (double)g_created_total
                             : 1.0;
        double fairness = 1.0 / (1.0 + (double)g_corpus[i].visits);
        if (novelty > 1.0) novelty = 1.0;
        weights[i] = 0.6 * novelty + 0.4 * fairness;
        total += weights[i];
      }
      double r = ((double)(rnd() >> 11) / (double)(1ULL << 53)) * total;
      for (size_t i = 0; i < g_corpus_len; ++i) {
        r -= weights[i];
        if (r <= 0.0) return i;
      }
      return g_corpus_len - 1;
    }
    default: {
      /* P_FULL: static structure combined with queue feedback, weighted random. */
      double total = 0.0;
      double *weights = (double *)alloca(sizeof(double) * g_corpus_len);
      for (size_t i = 0; i < g_corpus_len; ++i) {
        double novelty = g_created_total > 1
                             ? (double)(g_corpus[i].created_seq + 1) / (double)g_created_total
                             : 1.0;
        double fairness = 1.0 / (1.0 + (double)g_corpus[i].visits);
        if (novelty > 1.0) novelty = 1.0;
        double feedback = 0.6 * novelty + 0.4 * fairness;
        weights[i] = 0.5 * g_corpus[i].static_score + 0.5 * feedback;
        total += weights[i];
      }
      double r = ((double)(rnd() >> 11) / (double)(1ULL << 53)) * total;
      for (size_t i = 0; i < g_corpus_len; ++i) {
        r -= weights[i];
        if (r <= 0.0) return i;
      }
      return g_corpus_len - 1;
    }
  }
}

/* ---------------------------------------------------------------- mutation */

/*
 * Textbook havoc, deliberately unremarkable: flip a bit, replace a byte, insert, delete,
 * arithmetically nudge a JSON-ish character, or splice with another corpus entry.
 *
 * It is constant across arms on purpose. A cleverer mutator would make a scheduling
 * difference harder to see, not easier, and would give a reader a second explanation for
 * every result.
 */
static size_t mutate(uint8_t *buf, size_t size, size_t max_size, Policy policy) {
  (void)policy;
  int rounds = 1 + (int)(rnd() % 8);
  for (int r = 0; r < rounds; ++r) {
    if (size == 0) {
      buf[0] = (uint8_t)rnd();
      size = 1;
      continue;
    }
    switch (rnd() % 6) {
      case 0: { /* flip a bit */
        size_t at = rnd_below(size);
        buf[at] ^= (uint8_t)(1u << (rnd() % 8));
        break;
      }
      case 1: { /* replace a byte */
        buf[rnd_below(size)] = (uint8_t)rnd();
        break;
      }
      case 2: { /* interesting character, biased towards JSON syntax */
        static const char interesting[] = "{}[]\",:0123456789-+.eE\\/tnu f\r\n\t";
        buf[rnd_below(size)] = (uint8_t)interesting[rnd_below(sizeof(interesting) - 1)];
        break;
      }
      case 3: { /* insert a byte */
        if (size < max_size) {
          size_t at = rnd_below(size + 1);
          memmove(buf + at + 1, buf + at, size - at);
          buf[at] = (uint8_t)rnd();
          ++size;
        }
        break;
      }
      case 4: { /* delete a span */
        if (size > 1) {
          size_t len = 1 + rnd_below(size / 2 + 1);
          size_t at = rnd_below(size - len + 1);
          memmove(buf + at, buf + at + len, size - at - len);
          size -= len;
        }
        break;
      }
      default: { /* splice a span from another seed */
        if (g_corpus_len > 1 && size > 0) {
          size_t other = rnd_below(g_corpus_len);
          size_t take = 1 + rnd_below(g_corpus[other].size);
          size_t at = rnd_below(size);
          size_t n = take < size - at ? take : size - at;
          if (n > 0) memcpy(buf + at, g_corpus[other].data, n);
        }
        break;
      }
    }
  }
  return size;
}

/* ---------------------------------------------------------------- corpus growth */

static void corpus_add(const uint8_t *data, size_t size) {
  if (g_corpus_len >= MAX_CORPUS) return;
  Seed *seed = &g_corpus[g_corpus_len];
  seed->data = (uint8_t *)malloc(size ? size : 1);
  if (!seed->data) return;
  memcpy(seed->data, data, size);
  seed->size = size;
  seed->visits = 0;
  seed->created_seq = (uint32_t)g_created_total++;
  seed->static_score = static_score(data, size);
  ++g_corpus_len;
}

/* ---------------------------------------------------------------- crash saving */

static const char *g_crash_dir = NULL;
static uint64_t g_crashes = 0;

static void save_crash(const uint8_t *data, size_t size, int signal_number) {
  if (g_crash_dir == NULL || g_crashes >= MAX_CRASHES) return;
  char path[512];
  snprintf(path, sizeof(path), "%s/crash-%04llu-sig%02d", g_crash_dir,
           (unsigned long long)g_crashes, signal_number);
  FILE *f = fopen(path, "wb");
  if (!f) return;
  fwrite(data, 1, size, f);
  fclose(f);
  ++g_crashes;
}

/* ---------------------------------------------------------------- one execution */

static void coverage_clear(void);
static int coverage_is_new(void);

/*
 * Run the target once on `data`, in a forked child, and bring the coverage counters back.
 *
 * The counters live in the target's own data, so a plain fork loses them: the child's writes
 * are copy-on-write and vanish when it exits. The first version of this loop did exactly that
 * and reported 11 edges for a target with 1097 - a fuzzing loop that cannot see coverage is
 * not coverage-guided, it is random. AFL++ solves this with a shared-memory map; here the
 * child writes its counter array down a pipe, which is a few microseconds and keeps the
 * instrumentation entirely stock.
 *
 * Returns 0 for a clean run, or the terminating signal. Newly-covered counters are merged
 * into `g_seen` and counted in `g_edges_seen`.
 */
static int run_one(const uint8_t *data, size_t size) {
  int fds[2];
  if (pipe(fds) != 0) return -1;

  coverage_clear(); /* so the child inherits a zeroed map */

  pid_t pid = fork();
  if (pid < 0) {
    close(fds[0]);
    close(fds[1]);
    return -1;
  }
  if (pid == 0) {
    close(fds[0]);
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      dup2(devnull, STDOUT_FILENO);
      dup2(devnull, STDERR_FILENO);
      close(devnull);
    }
    LLVMFuzzerTestOneInput(data, size);
    if (g_counter_count) {
      size_t sent = 0;
      while (sent < g_counter_count) {
        ssize_t n = write(fds[1], g_counters + sent, g_counter_count - sent);
        if (n <= 0) break;
        sent += (size_t)n;
      }
    }
    close(fds[1]);
    _exit(0);
  }

  close(fds[1]);
  static uint8_t received[MAX_COUNTERS];
  size_t got = 0;
  while (got < g_counter_count) {
    ssize_t n = read(fds[0], received + got, g_counter_count - got);
    if (n <= 0) break;
    got += (size_t)n;
  }
  close(fds[0]);

  int status = 0;
  if (waitpid(pid, &status, 0) < 0) return -1;

  /* A signal means the run did not complete, so partial counter data is not trusted. */
  if (WIFSIGNALED(status)) return WTERMSIG(status);

  if (got == g_counter_count) {
    for (size_t i = 0; i < g_counter_count; ++i) {
      if (received[i] != 0 && g_seen[i] == 0) {
        g_seen[i] = 1;
        ++g_edges_seen;
        g_new_edges = 1;
      }
    }
  }
  return 0;
}

static int coverage_is_new(void) {
  int is_new = g_new_edges;
  g_new_edges = 0;
  return is_new;
}

static void coverage_clear(void) {
  if (g_counter_count) memset(g_counters, 0, g_counter_count);
}

/* ---------------------------------------------------------------- main loop */

static double now_seconds(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void load_seed_dir(const char *dir) {
  /* The starting corpus is passed as a directory of files; the harness never invents its
   * own starting points, because a different start would be a different experiment. */
  char cmd[1024];
  snprintf(cmd, sizeof(cmd), "ls -1 '%s' 2>/dev/null", dir);
  FILE *pipe = popen(cmd, "r");
  if (!pipe) return;
  char name[512];
  while (fgets(name, sizeof(name), pipe)) {
    size_t len = strlen(name);
    while (len && (name[len - 1] == '\n' || name[len - 1] == '\r')) name[--len] = '\0';
    if (!len) continue;
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "rb");
    if (!f) continue;
    static uint8_t buf[MAX_INPUT];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    if (n) corpus_add(buf, n);
  }
  pclose(pipe);
}

int main(int argc, char **argv) {
  const char *policy_arg = getenv("FUZZLAB_POLICY");
  const char *seed_arg = getenv("FUZZLAB_SEED");
  const char *budget_arg = getenv("FUZZLAB_BUDGET");
  const char *corpus_dir = getenv("FUZZLAB_CORPUS");
  const char *out_arg = getenv("FUZZLAB_OUT");
  const char *stats_arg = getenv("FUZZLAB_STATS");
  const char *max_execs_arg = getenv("FUZZLAB_MAX_EXECS");

  Policy policy = parse_policy(policy_arg);
  g_rng ^= seed_arg ? (uint64_t)strtoull(seed_arg, NULL, 10) : 1ULL;
  double budget = budget_arg ? atof(budget_arg) : 60.0;
  /* Execution budget, in executions rather than seconds.
   *
   * A scheduling comparison must hold the amount of *work* constant, not the wall clock. This
   * loop forks per execution while libFuzzer runs in-process, so a wall-clock budget would
   * measure the fork overhead - 170 execs/s here against 39,601/s for libFuzzer - and would
   * report that difference as a scheduling result. */
  uint64_t max_execs = max_execs_arg ? strtoull(max_execs_arg, NULL, 10) : 0;
  g_crash_dir = out_arg;

  g_corpus = (Seed *)calloc(MAX_CORPUS, sizeof(Seed));
  if (!g_corpus) return 2;

  load_seed_dir(corpus_dir ? corpus_dir : "in");
  if (g_corpus_len == 0) {
    fprintf(stderr, "no seeds in %s\n", corpus_dir ? corpus_dir : "in");
    return 2;
  }

  /* `seen` must exist before the first coverage comparison - an earlier version called
   * coverage_is_new() here with g_seen still NULL, which segfaulted before the loop started
   * and would have looked like "the fuzzer found nothing". */
  g_seen = (uint8_t *)calloc(g_counter_count ? g_counter_count : 1, 1);
  if (!g_seen) return 2;

  /* Prime the coverage map with the starting corpus, so the first mutation is judged
   * against what the seeds already reach rather than against nothing. */
  for (size_t i = 0; i < g_corpus_len; ++i) {
    coverage_clear();
    int sig = run_one(g_corpus[i].data, g_corpus[i].size);
    if (sig > 0) {
      /* A seed that crashes is a finding and is saved; it is not a reason to abort. */
      save_crash(g_corpus[i].data, g_corpus[i].size, sig);
    }
    coverage_is_new();
  }

  double started = now_seconds();
  double deadline = started + budget;
  uint64_t runs = 0;

  while (now_seconds() < deadline && (max_execs == 0 || runs < max_execs)) {
    size_t index = pick_seed(policy);
    Seed *seed = &g_corpus[index];
    ++seed->visits;

    static uint8_t buffer[MAX_INPUT];
    size_t size = seed->size < MAX_INPUT ? seed->size : MAX_INPUT;
    memcpy(buffer, seed->data, size);
    size = mutate(buffer, size, MAX_INPUT, policy);

    coverage_clear();
    int sig = run_one(buffer, size);
    ++runs;
    ++g_execs;

    if (sig > 0) {
      save_crash(buffer, size, sig);
      continue;
    }
    if (coverage_is_new()) {
      corpus_add(buffer, size);
      g_execs_since_new = 0;
    } else {
      ++g_execs_since_new;
    }
  }

  double elapsed = now_seconds() - started;
  uint64_t crashes = g_crashes;

  if (stats_arg) {
    FILE *f = fopen(stats_arg, "w");
    if (f) {
      fprintf(f,
              "{\n"
              "  \"policy\": \"%s\",\n"
              "  \"seed\": %s,\n"
              "  \"budget_s\": %.1f,\n"
              "  \"max_execs\": %llu,\n"
              "  \"wall_s\": %.2f,\n"
              "  \"execs\": %llu,\n"
              "  \"execs_per_s\": %.1f,\n"
              "  \"edges_found\": %llu,\n"
              "  \"counter_count\": %zu,\n"
              "  \"corpus_size\": %zu,\n"
              "  \"crashes\": %llu\n"
              "}\n",
              policy_name(policy), seed_arg ? seed_arg : "1", budget,
              (unsigned long long)max_execs, elapsed,
              (unsigned long long)runs,
              elapsed > 0 ? (double)runs / elapsed : 0.0,
              (unsigned long long)g_edges_seen, g_counter_count, g_corpus_len,
              (unsigned long long)crashes);
      fclose(f);
    }
  }
  printf("policy=%s execs=%llu edges=%llu corpus=%zu crashes=%llu wall=%.1fs\n",
         policy_name(policy), (unsigned long long)runs, (unsigned long long)g_edges_seen,
         g_corpus_len, (unsigned long long)crashes, elapsed);
  return 0;
}
