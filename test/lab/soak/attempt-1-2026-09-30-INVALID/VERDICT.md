# Attempt 1 — INVALID

Started 2026-09-30T17:17:10Z at commit ebf60eb.

| | |
|---|---|
| Cycles recorded | 668 |
| Cycles expected at 60s | ~1,380 |
| Largest gap between cycles | 39,439 s (about 11 hours) |
| Gaps over 180 s | 5 |
| Reached 86,400 s | **No** — last cycle at 82,954 s |
| Finish marker | **None** — process died |
| Broken-harness cycles | 0 |
| Outcome every cycle | FAILURE / 3 of 4 addresses (correct) |
| RSS | 1,392–2,112 KB, no growth trend |
| Open FDs | 10 throughout |

**Why it is invalid.** The host slept. Wall-clock "elapsed" kept advancing
across the 11-hour hole, so the run looked like it had covered most of a day
when roughly half of it was never executed. The harness had no way to notice.

**What it still shows.** Over 668 real cycles the classifier was correct every
time, the harness never broke, and neither memory nor file descriptors grew.
That is real evidence about leaks. It is not evidence of 24 hours of
continuous unattended operation, which is what item 089 requires.

**What changed.** The harness now holds a `caffeinate -i -s` assertion and
records any inter-cycle gap above three intervals as `INVALIDATING_GAP`.
