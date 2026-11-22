# Évaluation /16 — par app (benign=dérive hold-out, malware=7 C2 réels + synthétique co-hébergé)
# positif = malveillant · TP=malware bloqué · FN=malware raté(fuite) · TN=bénin laissé · FP=bénin bloqué

| app | bénin | malware | TP | FP | TN | FN | accuracy | precision | recall | F1 | FPR | FNR |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| dropbox | 8 | 15 | 10 | 2 | 6 | 5 | 0.70 | 0.83 | 0.67 | 0.74 | 0.25 | 0.33 |
| faceswitch | 15 | 22 | 15 | 2 | 13 | 7 | 0.76 | 0.88 | 0.68 | 0.77 | 0.13 | 0.32 |
| lequipe | 72 | 79 | 28 | 26 | 46 | 51 | 0.49 | 0.52 | 0.35 | 0.42 | 0.36 | 0.65 |
| meteo | 30 | 37 | 20 | 6 | 24 | 17 | 0.66 | 0.77 | 0.54 | 0.63 | 0.20 | 0.46 |
| ninegag | 34 | 41 | 20 | 5 | 29 | 21 | 0.65 | 0.80 | 0.49 | 0.61 | 0.15 | 0.51 |
| pokemongo | 12 | 19 | 12 | 3 | 9 | 7 | 0.68 | 0.80 | 0.63 | 0.71 | 0.25 | 0.37 |
| skype | 81 | 88 | 29 | 20 | 61 | 59 | 0.53 | 0.59 | 0.33 | 0.42 | 0.25 | 0.67 |
| viber | 39 | 46 | 18 | 9 | 30 | 28 | 0.56 | 0.67 | 0.39 | 0.49 | 0.23 | 0.61 |
| **MOYENNE ± σ** | | | | | | | **0.63±0.09** | 0.73±0.13 | 0.51±0.14 | 0.60±0.14 | 0.23±0.07 | 0.49±0.14 |

**Lecture** : TP = vrais C2 + malware non-lié (bloqués) ; **FN = malware co-hébergé (même /16 que l'app → fuite du /16)**.
lequipe/skype ont beaucoup de plages /16 → plus de malware co-hébergé fuit → recall plus bas.
