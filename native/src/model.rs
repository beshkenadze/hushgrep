use crate::{Span, source::Source};
use anyhow::{Result, anyhow, ensure};
use ort::{session::Session, value::Tensor};
use serde::Deserialize;
use std::{
    collections::{BTreeSet, HashMap},
    fs,
    path::Path,
};
use tokenizers::Tokenizer;

#[derive(Deserialize)]
struct Manifest {
    labels: Vec<String>,
    threshold: f32,
}

pub struct Model {
    encoder: Session,
    head: Session,
    tok: Tokenizer,
    schema: Vec<i64>,
    queries: Vec<usize>,
    cache: HashMap<String, Vec<i64>>,
    max_words: usize,
    unknown: i64,
    threshold: f32,
}

struct Row {
    ids: Vec<i64>,
    first: Vec<usize>,
    offsets: Vec<Span>,
}

impl Model {
    pub fn load(base: &Path) -> Result<Self> {
        ort::init_from(base.join("lib/libonnxruntime.so.1.32.0"))?.commit();
        let dir = base.join("model");
        let session = |name| -> Result<Session> {
            Ok(Session::builder()?
                .with_intra_threads(4)
                .map_err(|_| anyhow!("ORT threads"))?
                .with_inter_threads(1)
                .map_err(|_| anyhow!("ORT threads"))?
                .with_log_level(ort::logging::LogLevel::Error)
                .map_err(|_| anyhow!("ORT logging"))?
                .commit_from_file(dir.join(name))?)
        };
        let manifest: Manifest = serde_json::from_slice(&fs::read(dir.join("export.json"))?)?;
        let config: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join("config.json"))?)?;
        let tok =
            Tokenizer::from_file(dir.join("tokenizer.json")).map_err(|_| anyhow!("tokenizer"))?;
        let unknown = tok
            .token_to_id("[UNK]")
            .ok_or_else(|| anyhow!("missing unknown token"))? as i64;
        let mut model = Self {
            encoder: session("encoder.onnx")?,
            head: session("boundary.onnx")?,
            tok,
            unknown,
            threshold: manifest.threshold,
            max_words: config["max_len"]
                .as_u64()
                .ok_or_else(|| anyhow!("max_len"))? as usize,
            schema: vec![],
            queries: vec![],
            cache: HashMap::new(),
        };
        for word in ["(", "[P]", "entities", "("] {
            model.schema_word(word)?;
        }
        for label in manifest.labels {
            model.queries.push(model.schema.len());
            model.schema_word("[E]")?;
            model.schema_word(&label)?;
        }
        for word in [")", ")", "[SEP_TEXT]"] {
            model.schema_word(word)?;
        }
        Ok(model)
    }

    fn tokens(&self, word: &str) -> Result<Vec<i64>> {
        Ok(self
            .tok
            .encode(word, false)
            .map_err(|_| anyhow!("tokenization failed"))?
            .get_ids()
            .iter()
            .map(|&i| i64::from(i))
            .collect())
    }
    fn schema_word(&mut self, word: &str) -> Result<()> {
        let ids = self.tokens(word)?;
        self.schema.extend(ids);
        Ok(())
    }
    fn row(&mut self, text: &str) -> Result<Row> {
        let splitter = re!(
            r"(?i)https?://\S+|www\.\S+|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}|@[a-z0-9_]+|[\pL\pN_\pM\x{200c}\x{200d}]+(?:[-_][\pL\pN_\pM\x{200c}\x{200d}]+)*|\S"
        );
        let mut row = Row {
            ids: self.schema.clone(),
            first: vec![],
            offsets: vec![],
        };
        for m in splitter.find_iter(text).take(self.max_words) {
            let word = m.as_str().to_lowercase();
            if !self.cache.contains_key(&word) {
                let mut ids = self.tokens(&word)?;
                if ids.is_empty() {
                    ids.push(self.unknown);
                }
                if self.cache.len() >= 32768 {
                    self.cache.clear();
                }
                self.cache.insert(word.clone(), ids);
            }
            row.first.push(row.ids.len());
            row.offsets.push((m.start(), m.end()));
            row.ids.extend_from_slice(&self.cache[&word]);
        }
        Ok(row)
    }
    fn predict(&mut self, inputs: &[&str]) -> Result<Vec<Vec<Span>>> {
        let mut rows = Vec::new();
        for text in inputs {
            if text.ends_with(['.', '!', '?']) {
                rows.push(self.row(text)?);
            } else {
                rows.push(self.row(&format!("{text}."))?);
            }
        }
        let b = rows.len();
        let s = rows.iter().map(|r| r.ids.len()).max().unwrap();
        let w = rows.iter().map(|r| r.first.len()).max().unwrap();
        let q = self.queries.len();
        let mut ids = vec![0i64; b * s];
        let mut attn = vec![0i64; b * s];
        for (i, r) in rows.iter().enumerate() {
            ids[i * s..i * s + r.ids.len()].copy_from_slice(&r.ids);
            attn[i * s..i * s + r.ids.len()].fill(1);
        }
        let encoded = self.encoder.run(ort::inputs![
            "input_ids"=>Tensor::from_array(([b,s],ids))?,
            "attention_mask"=>Tensor::from_array(([b,s],attn))?])?;
        let (shape, h) = encoded["hidden_states"].try_extract_tensor::<f32>()?;
        let width = shape[2] as usize;
        let mut output = Vec::with_capacity(b);
        for (i, r) in rows.iter().enumerate() {
            let state = |pos: usize| &h[(i * s + pos) * width..(i * s + pos + 1) * width];
            let mut words = vec![0f32; w * width];
            let mut mask = vec![false; w];
            for (j, &pos) in r.first.iter().enumerate() {
                words[j * width..(j + 1) * width].copy_from_slice(state(pos));
                mask[j] = true;
            }
            let queries: Vec<f32> = self
                .queries
                .iter()
                .flat_map(|&p| state(p).iter().copied())
                .collect();
            let pred=self.head.run(ort::inputs![
                "token_states"=>Tensor::from_array(([1,w,width],words))?, "text_mask"=>Tensor::from_array(([1,w],mask))?,
                "query_states"=>Tensor::from_array(([1,q,width],queries))?, "query_mask"=>Tensor::from_array(([1,q],vec![true;q]))?])?;
            let (shape, logits) = pred["pair_logits"].try_extract_tensor::<f32>()?;
            let k = shape[2] as usize;
            let (_, idx) = pred["candidate_indices"].try_extract_tensor::<i64>()?;
            let (_, valid) = pred["candidate_valid"].try_extract_tensor::<bool>()?;
            let (_, null) = pred["null_logits"].try_extract_tensor::<f32>()?;
            ensure!(
                logits.len() == q * k
                    && idx.len() == 2 * q * k
                    && valid.len() == q * k
                    && null.len() == q
            );
            let mut spans = Vec::new();
            for (label, &abstain) in null.iter().enumerate() {
                if abstain > 0. {
                    continue;
                }
                let mut candidates = vec![];
                for t in label * k..(label + 1) * k {
                    if !valid[t] {
                        continue;
                    }
                    let p = 1.0 / (1.0 + (-logits[t].clamp(-80., 80.)).exp());
                    if p >= 0.1 {
                        candidates.push((p, idx[2 * t] as usize, idx[2 * t + 1] as usize));
                    }
                }
                for (p, a, end) in resolve(candidates) {
                    if p >= self.threshold && a < end && end <= r.offsets.len() {
                        spans.push((r.offsets[a].0, r.offsets[end - 1].1));
                    }
                }
            }
            output.push(spans);
        }
        Ok(output)
    }
    pub fn scan(&mut self, files: &[Source]) -> Result<Vec<BTreeSet<Span>>> {
        let mut found = vec![BTreeSet::new(); files.len()];
        let mut locations: HashMap<&str, Vec<(usize, usize, usize, usize)>> = HashMap::new();
        let mut count = 0;
        let mut flush =
            |locations: &mut HashMap<&str, Vec<(usize, usize, usize, usize)>>| -> Result<()> {
                let mut keys: Vec<_> = locations.keys().copied().collect();
                keys.sort_by_cached_key(|s| (s.chars().count(), *s));
                for batch in keys.chunks(8) {
                    for (window, pred) in batch.iter().zip(self.predict(batch)?) {
                        for (a, end) in pred {
                            let end = end.min(window.len());
                            for &(i, lo, left, right) in &locations[*window] {
                                if a < end && (left..right).contains(&(lo + a)) {
                                    found[i].insert((lo + a, lo + end));
                                }
                            }
                        }
                    }
                }
                locations.clear();
                Ok(())
            };
        for (i, file) in files.iter().enumerate() {
            let l = &file.lines;
            for n in 0..l.len() - 1 {
                let lo = l[n.saturating_sub(2)];
                let hi = l[(n + 3).min(l.len() - 1)];
                locations
                    .entry(&file.text[lo..hi])
                    .or_default()
                    .push((i, lo, l[n], l[n + 1]));
                count += 1;
                if count == 256 {
                    flush(&mut locations)?;
                    count = 0;
                }
            }
        }
        if count > 0 {
            flush(&mut locations)?;
        }
        Ok(found)
    }
}

// Weighted interval scheduling, with GLiNER's confidence/start/end tie ordering.
fn resolve(mut candidates: Vec<(f32, usize, usize)>) -> Vec<(f32, usize, usize)> {
    candidates.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)).then(a.2.cmp(&b.2)));
    let mut seen = BTreeSet::new();
    candidates.retain(|&(_, a, b)| seen.insert((a, b)));
    let mut order: Vec<_> = (0..candidates.len()).collect();
    order.sort_by_key(|&i| (candidates[i].2, candidates[i].1, i));
    let mut best = vec![(0.0f64, Vec::<usize>::new())];
    for (i, &rank) in order.iter().enumerate() {
        let (p, start, _) = candidates[rank];
        let prev = order[..i].partition_point(|&j| candidates[j].2 <= start);
        let (sum, mut selection) = best[prev].clone();
        let sum = sum + f64::from(p);
        selection.insert(selection.partition_point(|&r| r < rank), rank);
        let last = &best[i];
        if sum > last.0
            || (sum == last.0
                && (selection.len() > last.1.len()
                    || (selection.len() == last.1.len() && selection < last.1)))
        {
            best.push((sum, selection));
        } else {
            best.push(last.clone());
        }
    }
    best.pop()
        .unwrap()
        .1
        .into_iter()
        .map(|i| candidates[i])
        .collect()
}
