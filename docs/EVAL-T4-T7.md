# Protocolo de comparación multiagente vs. monolítico — resultados (T4–T7)

**Fecha:** 2026-09-15
**Autores:** Juan Sebastián Fandiño Novoa & Miguel Ángel Bonilla Torres — USB Bogotá
**Objetivo de tesis cubierto:** 7 — "Definir un protocolo reproducible para comparar la arquitectura multiagente con un modelo monolítico"

## Resumen ejecutivo

Se definió el baseline monolítico (T4), se construyó un corpus mixto real+sintético de 600 casos (T5), se corrió la comparación completa contra el pipeline de 5 señales, y se recalibró el umbral de decisión θ vía análisis ROC (T6). El pipeline supera al baseline con significancia estadística (McNemar, p<0.001). La recalibración de θ reveló un hallazgo de seguridad no trivial — documentado en detalle en la sección 4 — que llevó a elegir un umbral más conservador que el matemáticamente óptimo, priorizando la robustez del sistema ante fallas de servicios externos sobre el recall máximo.

## 1. Baseline monolítico (T4)

**Decisión:** `pirocheto/phishing-url-detection` (HuggingFace), un clasificador URL-only standalone. Ya está integrado en el pipeline como una de las 5 señales (`agent_scores.s_hf`), lo que permite derivar **ambos** veredictos —baseline y pipeline— de una sola llamada a `/api/v1/analyze` sobre el mismo caso: comparación limpia, sin doble costo de inferencia ni desalineación de splits.

```
baseline_verdict = PHISHING  si  s_hf >= 0.5   (umbral estándar del clasificador)
pipeline_verdict = response.verdict             (fusión de las 5 señales)
```

Implementación: `scripts/eval_baseline_vs_pipeline.py`.

## 2. Corpus de evaluación (T5)

| Clase | N | Fuente |
|---|---|---|
| Phishing IDN sintético | 150 | `scripts/generate_idn_corpus.py` — 1 sustitución de confusable TR#39 por dominio, sobre el índice top-1M (metodología ShamFinder, Suzuki et al. 2019) |
| Phishing real (no-IDN) | 150 | HuggingFace `imanoop7/phishing_url_classification` |
| Legítimo | 300 | 150 del índice top-1M (posiciones 1000–50000, evitando los dominios usados como base de los homógrafos) + 150 del mismo dataset HF |
| Phishing IDN real | **0** | No encontrado — ver limitación abajo |
| **Total** | **600** | |

**Limitación documentada:** no se encontraron homógrafos IDN reales en los datasets públicos de HuggingFace evaluados (`ealvaradob/phishing-dataset`, `pirocheto/phishing-url`, `imanoop7/phishing_url_classification`, `Naren1704/phishing-dataset`, `AreLit/PhishNChips` — los dos últimos con problemas de carga no relacionados). Es un hallazgo consistente con la literatura: los homógrafos IDN reales son raros y no están catalogados sistemáticamente en los feeds públicos de phishing, lo cual es precisamente la motivación para el corpus sintético (ShamFinder y trabajos similares usan la misma estrategia por la misma razón).

**Nota metodológica:** se descartó usar `pirocheto/phishing-url` (el dataset) como fuente de phishing real porque es del mismo autor que el modelo baseline (`pirocheto/phishing-url-detection`) — evaluar el baseline contra datos de su propio entrenamiento habría sido *data leakage*.

La corrida se ejecutó contra una instancia local del backend (Docker Compose vía Podman) para no contaminar el RAG ni la tabla de incidentes del backend de producción con datos sintéticos de evaluación.

## 3. Resultado de la comparación (T5 + T7)

**600 casos evaluados, 0 errores.**

### Con el θ vigente al momento de correr (0.70, heredado del diseño original de 3 señales)

| Métrica | Baseline (HF standalone) | Pipeline (5 señales) |
|---|---|---|
| Precision | 0.5443 | **1.0000** |
| Recall | 0.8600 | 0.4233 |
| F1 | 0.6667 | 0.5948 |
| Accuracy | 0.5700 | 0.7117 |

McNemar: χ²=17.42, p=3×10⁻⁵ (significativo), favorece al pipeline (245 casos donde el pipeline acierta y el baseline falla, contra 160 a la inversa).

### Con el θ recalibrado (0.30 — ver sección 4)

| Métrica | Baseline | Pipeline |
|---|---|---|
| Precision | 0.5443 | **1.0000** |
| Recall | 0.8600 | 0.6667 |
| F1 | 0.6667 | **0.8000** |
| Accuracy | 0.5700 | **0.8333**† |

McNemar (recalculado): χ²=72.07, p<0.001, favorece al pipeline con margen aún mayor (250 casos donde el pipeline acierta y el baseline falla, contra 92 a la inversa).

† accuracy derivada de tp=200, fp=0, fn=100, tn=300 sobre 600 casos.

**Interpretación:** en ambos umbrales, el pipeline multiagente supera al baseline monolítico con significancia estadística. El baseline tiene mejor recall pero a costa de una precision pobre (56%–57%) — más de un tercio de sus alertas de phishing son falsas alarmas sobre dominios legítimos, un problema real de "alert fatigue" para un sistema de seguridad. El pipeline nunca genera un falso positivo en este corpus (precision=1.0 en ambos umbrales).

## 4. Recalibración de θ vía ROC (T6)

**AUC = 0.9867** sobre los 600 casos — el `s_risk` del pipeline discrimina excelentemente entre phishing y legítimo en términos agregados.

Distribución de `s_risk` por clase:

| | p10 | p50 (mediana) | p90 |
|---|---|---|---|
| Phishing | 0.1625 | 0.355 | 0.5675 |
| Legítimo | 0.0023 | 0.10 | 0.115 |

La mediana de phishing real (0.355) está muy por debajo del θ=0.70 original — diseñado para un pipeline de 3 señales, nunca recalibrado tras sumar TI, WebProbe y el clasificador HF. Esto explica el recall pobre (0.42) observado con ese umbral: el sistema dejaba pasar como LEGITIMATE la mayoría del phishing real.

### El hallazgo de seguridad

Usando `core/calibration.py::choose_theta()` (la misma función pura que usa el job de recalibración adaptativa en producción, T12) con la loss asimétrica de la tesis (`L(θ) = λ·FP + (1-λ)·FN`, λ=0.30 — falsos negativos penalizados 3× más que falsos positivos), el óptimo matemático sobre este corpus es **θ=0.12**.

Al aplicar ese valor, la suite de tests de regresión (`tests/integration/test_phishing_evaluation.py::TestLegitimateDomainsNotFlagged`) detectó una falla: **cuando el LLM y el clasificador HF degradan simultáneamente a su valor neutral de fallback (0.5 cada uno — por ejemplo, ante una caída de servicio o timeout), cualquier dominio produce `s_risk = (1-γ)·0.5 = 0.25`, independientemente de su riesgo real.** Con θ=0.12, ese escenario de "sin información" habría producido veredicto PHISHING para cualquier dominio, incluyendo `google.com`, `github.com`, etc. — una violación directa del requisito no funcional de "degradación graciosa" (ningún fallo de señal individual debe bloquear el veredicto de forma incorrecta).

Se optó por **θ=0.30**: el valor más agresivo (más bajo) que conserva un margen real sobre ese piso de degradación de 0.25, en vez del óptimo matemático puro. Esto es una decisión de ingeniería deliberada, no un ajuste fino — prioriza la robustez del sistema ante fallas externas sobre la métrica de recall.

**Costo de esta decisión:** con θ=0.30, el pipeline no alcanza la meta interna de recall≥0.75 (obtiene 0.667). Con θ=0.12 sí la habría alcanzado (según el mismo corpus: precision=0.9628, recall=0.95), pero a costa de una vulnerabilidad real. Esta tensión —entre maximizar la detección y garantizar que el sistema no colapse en falsos positivos masivos ante una degradación de servicio— se documenta aquí explícitamente en vez de ocultarla eligiendo el umbral que mejor número produce.

### Corte SUSPICIOUS — pendiente

El diseño original tenía 3 niveles de veredicto (`PHISHING ≥ 0.70`, `SUSPICIOUS ≥ 0.40`, `LEGITIMATE` debajo), con 0.40 hardcodeado en `fusion_agent.py`. Al bajar θ a 0.30, ese 0.40 quedó *por encima* del nuevo umbral de PHISHING, invirtiendo el orden de los niveles.

El score de dominios legítimos en este corpus mostró dos valores discretos muy poblados (0.10 en 104/300 casos, 0.115 en 81/300 — probable artefacto estructural de la fórmula de fusión, no ruido aleatorio) pegados justo debajo del nuevo θ. Cualquier banda SUSPICIOUS colocada ahí dispararía falsas alarmas sobre entre el 27% y el 70% del tráfico legítimo, según dónde se ubique el corte.

**Se extrajo `SUSPICIOUS_THRESHOLD` como constante en `core/constants.py` y se colapsó igual a `THETA`** (la banda queda deshabilitada — el código de `_compute_verdict` sigue soportando 3 niveles, simplemente no se alcanza el tramo SUSPICIOUS hasta que se investigue el origen de esos pisos discretos y se defina un corte defendible). Esto queda como trabajo futuro explícito, fuera del alcance de T6.

## 5. Cambios en el código

- `core/constants.py`: `THETA` 0.70 → 0.30; nueva constante `SUSPICIOUS_THRESHOLD` (antes hardcodeada, ahora = `THETA`).
- `agents/fusion_agent.py`: `_compute_verdict` usa `SUSPICIOUS_THRESHOLD` en vez del literal `0.40`.
- 9 tests actualizados/agregados en `tests/unit/test_constants.py`, `tests/unit/test_fusion_agent.py`, `tests/unit/test_calibration.py` — incluyendo un invariante nuevo, `test_theta_above_neutral_degradation_floor`, que fija el piso de seguridad (0.25) como regla explícita para que una futura recalibración no vuelva a cruzarlo por accidente.
- Suite completa: **972 passed, 28 skipped, 92.61% cobertura.**

## 6. Reproducibilidad

Orquestador de un solo comando (valida que el LLM gateway responda con score real antes de gastar cuota de TI, corre el corpus completo, y ejecuta el análisis ROC de T6):

```bash
python -m scripts.run_t5_t6 --backend http://localhost:8000
```

Evidencia cruda (JSON, incluye resultado por caso individual):

- `reports/baseline_vs_pipeline_20260915_002802.json` — comparación T5/T7 (raw_results por caso: URL, veredicto de ambos modelos, s_risk, s_hf).
- `reports/t6_theta_recalibration_20260915_002802.json` — curva ROC completa, distribución de scores, recalibración de θ.
- `data/idn_synth.jsonl` — los 150 casos sintéticos generados (dominio base, sustitución, script Unicode usado).
- `data/legit_sample.jsonl` — los 150 dominios legítimos muestreados del top-1M.

## 7. Limitaciones explícitas

- El corpus no incluye phishing-IDN real (ver sección 2) — la comparación para ese subconjunto específico se apoya enteramente en el corpus sintético.
- La corrida fue contra un ambiente local, no el backend de producción desplegado (deliberado, para no contaminar datos reales).
- El corte SUSPICIOUS queda deshabilitado, no resuelto (sección 4).
- No se ejecutó una segunda corrida independiente para verificar estabilidad de las métricas entre corridas (una sola pasada de 600 casos) — dado el tamaño de la muestra y la significancia obtenida, se consideró suficiente para esta validación inicial, pero una réplica sería deseable antes de reportar los números como definitivos.
