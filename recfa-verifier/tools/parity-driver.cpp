/* Parity driver: exercises the vendored ReCFA verifier through the same C entry
 * point the Wasm component uses, but built natively. Its output is compared
 * against unmodified upstream `check` to prove the vendoring changed nothing.
 *
 * Build:
 *   c++ -O2 -std=gnu++14 -I../recfa-verifier-component/vendor \
 *       parity-driver.cpp ../recfa-verifier-component/vendor/check.cpp -o parity-driver
 *
 * Usage: same argv as upstream check(1).
 */
#include "recfa_entry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string>

static std::string slurp(const char *path) {
  std::string s;
  FILE *f = fopen(path, "rb");
  if (!f)
    return s;
  char buf[65536];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
    s.append(buf, n);
  fclose(f);
  return s;
}

int main(int argc, char **argv) {
  if (argc != 8) {
    fprintf(stderr,
            "usage: parity-driver <asm> <dot> <policyF> <policyM> <trace> "
            "<num_executions> <gcc|llvm>\n");
    return 2;
  }
  std::string a = slurp(argv[1]), d = slurp(argv[2]), F = slurp(argv[3]),
              M = slurp(argv[4]), T = slurp(argv[5]);

  recfa_vfs_put("asm", (const unsigned char *)a.data(), (unsigned long)a.size());
  recfa_vfs_put("dot", (const unsigned char *)d.data(), (unsigned long)d.size());
  recfa_vfs_put("F", (const unsigned char *)F.data(), (unsigned long)F.size());
  recfa_vfs_put("M", (const unsigned char *)M.data(), (unsigned long)M.size());
  recfa_vfs_put("trace", (const unsigned char *)T.data(), (unsigned long)T.size());

  recfa_result r;
  int rc = recfa_verify("asm", "dot", "F", "M", "trace", atoi(argv[6]), argv[7],
                        &r);

  printf("RESULT verdict=%d total=%lld unprocessed=%lld reconstructed=%lld "
         "M=%lu F=%lu site=%x target=%x main=%x ret=%x rc=%d\n",
         r.verdict, r.events_attested, r.events_unprocessed,
         r.events_reconstructed, r.policy_m_entries, r.policy_f_entries,
         r.violation_site, r.violation_target, r.main_addr, r.main_ret_addr, rc);
  return 0;
}
