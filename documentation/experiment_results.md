# Phase 3 Research Experiments (E1–E5)

All E1/E2 metrics and errors below are recomputed by `python src/evaluate_experiments.py` on the held-out processed test splits.
URL and email datasets are unpaired. E4 pairings are controlled exploratory combinations of actual test rows; they are not naturally paired examples, and no rows were used for training.
The fusion weights are specified design defaults, not tuned against these test results. The HTML fixtures are authored deterministic checks, not representative labeled observations.

## E1 — URL-only test evaluation

| Accuracy | Precision | Recall | F1-score | False positive rate | Confusion matrix `[[TN,FP],[FN,TP]]` |
|---:|---:|---:|---:|---:|---|
| 0.873645 | 0.678773 | 0.833936 | 0.748397 | 0.114804 | `[[52169, 6766], [2847, 14297]]` |

## E2 — Text-only test evaluation

| Accuracy | Precision | Recall | F1-score | False positive rate | Confusion matrix `[[TN,FP],[FN,TP]]` |
|---:|---:|---:|---:|---:|---|
| 0.985949 | 0.983756 | 0.989420 | 0.986580 | 0.017842 | `[[5780, 105], [68, 6359]]` |

## E3 — Static HTML fixture checks

These four authored fixtures only check structural behavior. Their pass rate is not a classifier accuracy estimate.

| Fixture | Expected behavior | Risk score | Check | Indicators |
|---|---|---:|---|---|
| benign_static_article | benign | 0.0000 | PASS | None |
| benign_plain_page | benign | 0.0000 | PASS | None |
| credential_harvesting_template | phishing_fixture | 0.8500 | PASS | Password input field detected, Hidden input field detected, Form submits to external domain, Iframe detected, Inline event handler detected |
| external_credential_form | phishing_fixture | 0.6500 | PASS | Password input field detected, Form submits to external domain |

## E4 — Controlled URL/text fusion comparisons

Protocol: pair the first held-out rows of matching ground-truth class in each independently shuffled test file, stopping at the smaller class count. Pairing by class and row order creates a controlled score-combination benchmark only; there is no sample-level relationship between paired URLs and emails. No training rows were fabricated or added. The reported values must not be interpreted as performance on naturally paired multimodal data.

Concordant pair counts: class 0 = 5,885; class 1 = 6,427.

| Method on selected concordant pairs | Accuracy | Precision | Recall | F1-score | FPR |
|---|---:|---:|---:|---:|---:|
| URL-only | 0.853558 | 0.882528 | 0.829936 | 0.855425 | 0.120646 |
| Text-only | 0.985949 | 0.983756 | 0.989420 | 0.986580 | 0.017842 |
| Late fusion | 0.991228 | 0.991751 | 0.991442 | 0.991597 | 0.009006 |

### Cross-class evidence conflicts

These cases have opposing source labels, so they are summarized without assigning a pair-level true label or calculating accuracy.

- `url_safe_text_phishing`: 6,427 pairs; mean fused score 0.670500; decisions `{'Legitimate': 228, 'Suspicious': 3045, 'Phishing': 3154}`.
- `url_phishing_text_safe`: 5,885 pairs; mean fused score 0.338851; decisions `{'Legitimate': 2531, 'Suspicious': 3111, 'Phishing': 243}`.

No E4 accuracy is reported for all three modalities because the project has no held-out paired URL/text/HTML examples.

## E5 — Held-out error analysis

Counts below are computed from actual URL/text test-set predictions. Short examples are excerpts from the provided test CSVs; row indices refer to their respective test files.

### Url model

- **FP: 6,766 errors.**
  - Median error URL length: 38.0 characters; 6,588 (97.4%) had no explicit token from the extractor's suspicious-token list.
  - Test row 10: true=0, predicted=1, score=0.58918; excerpt "accessottawa.com/business/photography/photo.htm"
  - Test row 13: true=0, predicted=1, score=0.65226; excerpt "emorymotorsports.com/outlaws"
  - Test row 20: true=0, predicted=1, score=0.75108; excerpt "trainstuff.info/railroads/k/kansascityterminal/kansascityterminal.htm"
  - Test row 34: true=0, predicted=1, score=0.54489; excerpt "acronyms.thefreedictionary.com/KPRS"
- **FN: 2,847 errors.**
  - Median error URL length: 36.0 characters; 2,847 (100.0%) had no explicit token from the extractor's suspicious-token list.
  - Test row 14: true=1, predicted=0, score=0.32251; excerpt "dorgashotel.com.br/"
  - Test row 28: true=1, predicted=0, score=0.43452; excerpt "raenaga12055.com/"
  - Test row 45: true=1, predicted=0, score=0.22058; excerpt "services.runescape.co.cm/m=forums/forums.wz?1439"
  - Test row 55: true=1, predicted=0, score=0.47668; excerpt "www.canalafrique.tv/components/com_banners/models/mail.html"

### Text model

- **FP: 105 errors.**
  - Median error text length: 358.0 characters; common error tokens: `[('httpsmcs', 139), ('msgs', 139), ('cusertm', 139), ('paceedu', 139), ('com', 111), ('email', 93), ('httpemreactcomgoaspbpla', 82), ('deliver', 65)]`.
  - Test row 97: true=0, predicted=1, score=0.62046; excerpt "california prices fun"
  - Test row 212: true=0, predicted=1, score=0.67529; excerpt "happy holidays wish wonderful holidays happy happy new year many blessings shirley"
  - Test row 257: true=0, predicted=1, score=0.51424; excerpt "emma kennedy dpcteaqmlfhairtricitycom pictures love bites meant censor ones ________________________________ dqcxzgkebrekxpencrackmicecom mailtodqcxzgkebrekxpencrackmicecom behalf eoin parker sent 16 october 2007 1240 undisclosedrecipients …"
  - Test row 311: true=0, predicted=1, score=0.69881; excerpt "6 1119 disc kinship terms 1113 steven straight comments brevity son sole factor involved since dad mom pattern father mother son different used true vocative used usuallypostposed bonding form brother different still since used either way m…"
- **FN: 68 errors.**
  - Median error text length: 826.5 characters; common error tokens: `[('site', 91), ('listing', 75), ('please', 72), ('information', 70), ('new', 58), ('email', 57), ('one', 52), ('list', 46)]`.
  - Test row 92: true=1, predicted=0, score=0.45046; excerpt "markusnilssonlandskronase outlook web network account password expire today change password please follow instructions visit outlook web digital intranet page access district desktop computers ie district drives vpn access outside district …"
  - Test row 272: true=1, predicted=0, score=0.33107; excerpt "venture reporter newsrisingtidestudioscom cmshttpwwwcmsummitcomimagesright_02gif cmshttpwwwcmsummitcomimagescms_titlegif dear friends online content business fantastic sound crazy perhaps advertising online taking chin past two years online…"
  - Test row 746: true=1, predicted=0, score=0.36816; excerpt "order shipment careamaznusshipment2co amazon order confirmation hello josemonkeyorg thank shopping us well send confirmation items ship details order 99149582161093584 shipment 1 2 arriving saturday august 15 view manage order ship mike haw…"
  - Test row 1051: true=1, predicted=0, score=0.30028; excerpt "wonderful short motion detectors 70 savings b e n b e n meds want info see difference today turn notifications www consummate mnsdhhj com sayonara html employers also asked list unusual questions asked job candidates buck funny things prese…"

## Interpretation limits

Text and URL results are from distinct source populations and are not directly comparable as a modality ablation. The controlled E4 pairing explores the configured aggregation rule, but cannot establish that fusion reduces real-world blind spots without a genuinely paired test corpus. E3 assesses implemented HTML rules on explicit fixtures only. All model outputs are decision support, not proof.
