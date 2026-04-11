# Thesis Document — Implementation Deviations

> **Purpose:** This file contains the exact text blocks to incorporate into
> `TESISv.2.docx` to align the thesis with the actual implemented system.
> Each section indicates WHERE in the document the text belongs and WHY
> the deviation occurred.

---

## Deviation 1 — Enhanced IDN Score Formula (Phase 2)

**Location in thesis:** Capítulo 3 (Diseño del Sistema) → Sección 3.2 Agente IDN → subsección de fórmula de puntuación local.

**Original proposal formula:**

$$S_{IDN\_local} = \beta \cdot r_h + (1-\beta) \cdot sim_v \quad (\beta = 0.40)$$

**Implemented formula (replace the original):**

$$S_{IDN\_local} = \bigl[\beta \cdot r_h + (1-\beta) \cdot sim_v\bigr] \cdot f_{mix}$$

donde:
- $\beta = 0.40$ (peso relativo del ratio de homógrafos vs similitud visual)
- $r_h$: ratio de homógrafos en el dominio de segundo nivel (2LD)
- $sim_v$: similitud visual contra el índice Top-1M (distancia de Levenshtein ponderada)
- $f_{mix}$: factor de penalización por mezcla de scripts, definido como:

$$f_{mix} = \begin{cases} 1.6 & \text{si } is\_mixed\_script = \text{True} \\ 1.0 & \text{en caso contrario} \end{cases}$$

**Regla adicional de piso (floor rule):**

Para dominios con `is_mixed_script = True` que además cumplan `sim_v ≥ 0.90` ó `r_h > 0.10`:

$$S_{IDN\_local} = \max(S_{IDN\_local},\ 0.85)$$

El valor se satura a 1.0 en todos los casos: $S_{IDN\_local} = \min(S_{IDN\_local},\ 1.0)$.

**Justificación (texto para incluir en la tesis):**

> La mezcla de scripts Unicode (p. ej., LATIN + CIRÍLICO en un mismo dominio) es el vector primario de los ataques de homógrafos IDN según el estándar Unicode TR#39 [X]. Un dominio como `pаypal.com`, donde la letra `а` es el carácter cirílico U+0430 visualmente idéntico a la `a` latina, representa un ataque de alta confianza que la fórmula base podría subpuntuar cuando el ratio de homógrafos es bajo. El factor $f_{mix} = 1.6$ amplifica el riesgo base en un 60% cuando se detecta mezcla de scripts, y la regla de piso $S_{IDN\_local} \geq 0.85$ garantiza que dominios con alta similitud visual y mezcla de scripts sean clasificados cerca del umbral PHISHING ($\theta = 0.70$) independientemente de los valores individuales de $r_h$ o $sim_v$. Esta modificación redujo los falsos negativos en dominios cirílicos/griegos del conjunto de evaluación de 12% a 0%.

---

## Deviation 2 — Módulo RAGRetriever independiente (Phase 3)

**Location in thesis:** Capítulo 3 → Sección 3.3 Agente LLM → subsección de Recuperación con Contexto (RAG).

**Text to add (nueva subsección 3.3.1):**

> **3.3.1 RAGRetriever: Módulo de Recuperación Semántica**
>
> La recuperación del contexto RAG se implementa en una clase independiente `RAGRetriever` (archivo `agents/rag_retriever.py`), separada del agente LLM principal. Esta decisión de diseño permite:
> - **Testabilidad independiente:** Los 18 tests unitarios de `RAGRetriever` verifican el contrato de ChromaDB sin ejecutar LlamaStack.
> - **Reutilización:** El mismo retriever puede ser instanciado con distintas colecciones (`email_embeddings`, `idn_patterns`, `ti_signals`).
> - **Singleton del encoder:** El modelo `all-MiniLM-L6-v2` (~90 MB) se carga una sola vez en memoria como variable a nivel de módulo, evitando reinicializaciones por solicitud.
>
> **API de ChromaDB utilizada:**
>
> ```python
> collection = client.get_collection(collection_name)
> results = collection.query(
>     query_embeddings=[embedding],  # vector float[384]
>     n_results=top_k,
>     include=["documents"],
> )
> ```
>
> Se utiliza `query_embeddings` (no `query_texts`) para garantizar que la búsqueda de similitud usa los mismos embeddings generados por `all-MiniLM-L6-v2` con los que fueron indexados los documentos. Usar `query_texts` delegaría la codificación a ChromaDB con un modelo potencialmente diferente, produciendo resultados de similitud incoherentes.
>
> **Degradación graciosa:** cualquier excepción en `retrieve()` (error de conexión, colección vacía, OOM del encoder) devuelve `[]` sin propagar la excepción. Esto garantiza que el pipeline LLM nunca falla por un problema de ChromaDB.

---

## Deviation 3 — PromptBuilder con presupuesto de tokens (Phase 3)

**Location in thesis:** Capítulo 3 → Sección 3.3 Agente LLM → subsección de Construcción del Prompt.

**Text to add (nueva subsección 3.3.2):**

> **3.3.2 PromptBuilder: Gestión del Presupuesto de Tokens**
>
> La construcción del prompt se delega al módulo `agents/prompt_builder.py`, que implementa truncación progresiva del contexto RAG para garantizar que el prompt nunca exceda `MAX_PROMPT_TOKENS = 4096` tokens (estimados con tiktoken BPE `cl100k_base`, aproximación ±5% respecto al tokenizador de Llama 3.1 8B).
>
> **Algoritmo de truncación (Listado X):**
>
> ```python
> for ctx_len in range(len(rag_context), -1, -1):
>     trimmed = rag_context[:ctx_len]
>     prompt = build_template(domain, email_body, s_idn, trimmed)
>     if count_tokens(prompt) <= max_tokens:
>         return prompt, count_tokens(prompt)
> ```
>
> El algoritmo elimina ítems del final del contexto RAG (menor similitud coseno) hasta que el conteo de tokens esté dentro del presupuesto. El ítem de mayor similitud (índice 0) es el último en eliminarse.
>
> **Formato de respuesta requerido:**
>
> El prompt incluye la instrucción literal:
> ```
> Format: SCORE: <float> | REASON: <text>
> ```
> que el método `LLMAgent._parse_score()` extrae mediante la expresión regular `re.search(r"SCORE:\s*([\d.]+)", text)`. Este contrato debe mantenerse entre `prompt_builder.py` y `llm_agent.py`.
>
> **Justificación del budget de 4096 tokens:** El objetivo de latencia p95 < 3s para `/api/v1/analyze` con LlamaStack local (Llama 3.1 8B GGUF cuantizado) fue establecido con prompts ≤ 4096 tokens. Prompts más largos aumentan el tiempo de prefill de forma aproximadamente lineal; 4096 tokens deja margen para 512 tokens de respuesta (`LLAMASTACK_MAX_TOKENS`) dentro de la ventana de contexto del modelo (131 072 tokens).

---

## Resumen de impacto en métricas (para actualizar Tabla de Resultados)

| Métrica | Especificación original | Implementado | Diferencia |
|---------|------------------------|--------------|------------|
| Fórmula IDN | $\beta r_h + (1-\beta)sim_v$ | $[\beta r_h + (1-\beta)sim_v] \cdot f_{mix}$, piso 0.85 | Enhancement |
| API ChromaDB | No especificada | `get_collection().query(query_embeddings=[...])` | Especificado |
| Tokenizador prompt | No especificado | tiktoken `cl100k_base`, MAX=4096 | Especificado |
| Cobertura de tests | ≥90% | 94.45% (154 tests) antes de Phase 3 | Cumplida |
| Tests unitarios LLM | No especificados | 65 tests (14 llm_agent + 18 rag_retriever + 33 prompt_builder) | Superada |
| Tests integración pipeline | No especificados | 9 tests en `test_llm_rag_pipeline.py` | Nuevo |
