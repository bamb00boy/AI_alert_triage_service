# data/alerts — sources and license

`alerts.jsonl` and `ground_truth.jsonl` are **derived from
[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)** by Samir Bousseaden,
which is licensed under the **GNU General Public License v3.0**. This folder is therefore distributed
under GPL-3.0 as well; the license text is in [LICENSE-GPL-3.0.txt](LICENSE-GPL-3.0.txt). The MIT
license at the repository root does not apply to the files in this folder.

How they were derived (`scripts/build_dataset.py`):

- Detections were produced by running [Hayabusa](https://github.com/Yamato-Security/hayabusa) with the
  [hayabusa-rules](https://github.com/Yamato-Security/hayabusa-rules) rule set (which includes
  [SigmaHQ](https://github.com/SigmaHQ/sigma) rules) over the EVTX samples. The alerts contain rule
  titles and rule IDs only, not rule content. Sigma rules are licensed under the
  [Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License); their authors are
  credited in those repositories.
- Ground-truth techniques come from the rules' ATT&CK tags (see `data/attack/LICENSE.txt` for the
  ATT&CK terms).
- Some network indicators were replaced with entries from the lists in `data/ti/` (see
  `data/ti/NOTICE.md`), and technique IDs were removed from event text.
