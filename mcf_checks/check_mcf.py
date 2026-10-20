#!/usr/bin/env python3
"""Cheap checks for multiple-choice evals.

The columns are detected per file. A row needs two or more choices and a gold
index. Letter answers (A, B, C) and 1-based numbers (correct_answer_num) are
converted to a 0-based index. choice1.. and solution0.. are choice columns.
A nested choices object ({text, label} plus answerKey) is expanded, and the
gold is the position of answerKey in that label list. The stem is premise
plus question for choice1.. rows, and prompt for solution0.. rows. Trailing
empty and "N/A" slots are dropped. Sentence pairs (sen / wrong_sen) are a
two-choice item whose gold is the grammatical sentence, and an empty stem is
expected.

    python check_mcq.py data/global-mmlu data/mmlu-prox include-base-44 data/multiblimp data/belebele

Point it at one directory per eval. A file whose columns are not a choice
layout below is ignored. A directory with no such file is skipped, and nothing
is written for it.

Per item:
  1. gold index is in range
  2. stem and every choice are non-empty
  3. choices are unique; gold repeats are called out
  4. no choice equals the stem
  5. choices are not bare keys unless the stem labels those keys
  6. stem mentions a missing attachment (review)
  7. gold choice text already appears in the stem (review)

Across rows, within one dataset and config:
  8. one gold index for the same stem and choices
  9. exact copies inside one split
  10. exact copies shared by more than one split (review)
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

import pyarrow.csv as pacsv
import pyarrow.parquet as pq

from attachment_markers import all_phrases

DATA_SUFFIXES = {".parquet", ".tsv", ".csv", ".jsonl", ".json"}
SPLIT_MARKERS = ("validation", "test", "train", "dev", "val")

# Fires only when every choice is a statement key. Digits are answers
# ("how many" items whose choices are 1, 2, 3, 4), so they are not keys.
BARE_KEY = re.compile(
    r"^(?:"
    r"[A-Da-d]"
    r"|[ivxIVX]{1,4}"
    r"|[ㄱ-ㅎ](?:\s*[,、/]\s*[ㄱ-ㅎ])*"
    r"|[A-Da-d](?:\s*[,、/]\s*[A-Da-d])+"
    r")$"
)
KEY_PARTS = re.compile(r"\s*[,、/]\s*")
LETTERS = "ABCDEFGHIJ"

# Review-only. Phrases for every eval language live in attachment_markers.
# A broad "see the figure" search is much noisier than this list, so each
# wording is a full phrase, not a single word such as "figure" or "above".
ATTACHMENT_MARKERS = all_phrases()

GOLD_IN_STEM_MIN_CHARS = 12
GOLD_IN_STEM_MIN_WORDS = 2
TRAILING_PLACEHOLDERS = {"n/a"}
_FOLD_TRANS = str.maketrans({
    "–": "-",
    "—": "-",
    "−": "-",
    "‑": "-",
    "’": "'",
    "‘": "'",
    "´": "'",
    "`": "'",
})
_ARABIC_MARKS = re.compile(r"[\u064b-\u0652\u0670\u0640]")


class _AttachmentIndex:
    """Longest-match search over the attachment phrases."""

    def __init__(self, phrases: tuple[str, ...]) -> None:
        self.original = {_fold_marker(phrase): phrase for phrase in phrases}
        self.goto: list[dict[str, int]] = [{}]
        self.fail = [0]
        self.out: list[list[str]] = [[]]
        for word in self.original:
            node = 0
            for ch in word:
                nxt = self.goto[node].get(ch)
                if nxt is None:
                    nxt = len(self.goto)
                    self.goto[node][ch] = nxt
                    self.goto.append({})
                    self.fail.append(0)
                    self.out.append([])
                node = nxt
            self.out[node].append(word)
        queue = list(self.goto[0].values())
        head = 0
        while head < len(queue):
            node = queue[head]
            head += 1
            for ch, nxt in self.goto[node].items():
                queue.append(nxt)
                fallback = self.fail[node]
                while fallback and ch not in self.goto[fallback]:
                    fallback = self.fail[fallback]
                landed = self.goto[fallback].get(ch, 0)
                self.fail[nxt] = 0 if landed == nxt else landed
                self.out[nxt] = self.out[nxt] + self.out[self.fail[nxt]]

    def find(self, text: str) -> str | None:
        best: str | None = None
        node = 0
        for ch in _fold_marker(text):
            while node and ch not in self.goto[node]:
                node = self.fail[node]
            node = self.goto[node].get(ch, 0)
            for word in self.out[node]:
                if best is None or len(word) > len(best):
                    best = word
        if best is None:
            return None
        return self.original[best]


def _fold_marker(text: str) -> str:
    return _ARABIC_MARKS.sub("", text.translate(_FOLD_TRANS).casefold())


_ATTACHMENT_INDEX = _AttachmentIndex(ATTACHMENT_MARKERS)


def _attachment_hit(question: str) -> str | None:
    return _ATTACHMENT_INDEX.find(question)


def stripped(value) -> str:
    if value is None:
        return ""
    return str(value).strip()


def data_files(root: Path) -> list[Path]:
    files = [
        path
        for path in root.rglob("*")
        if path.is_file() and path.suffix.lower() in DATA_SUFFIXES and path.name != ".gitattributes"
    ]
    return sorted(files)


def split_of(path: Path) -> str:
    name = path.name.lower()
    for marker in SPLIT_MARKERS:
        if name.startswith(marker + "-") or name.startswith(marker + "."):
            return "validation" if marker == "val" else marker
    return "all"


def read_records(path: Path) -> list[dict]:
    suffix = path.suffix.lower()
    if suffix == ".parquet":
        return pq.read_table(path).to_pylist()
    if suffix in {".csv", ".tsv"}:
        delimiter = "\t" if suffix == ".tsv" else ","
        table = pacsv.read_csv(path, parse_options=pacsv.ParseOptions(delimiter=delimiter))
        return table.to_pylist()
    if suffix == ".jsonl":
        records = []
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        return records
    text = path.read_text(encoding="utf-8")
    payload = json.loads(text)
    if isinstance(payload, list):
        return payload
    raise ValueError(f"{path} is not a list of records")


def columns_of(path: Path) -> list[str]:
    """Read just enough metadata to decide whether a file can be an MCQ eval."""
    suffix = path.suffix.lower()
    if suffix == ".parquet":
        return pq.ParquetFile(path).schema_arrow.names
    if suffix == ".jsonl":
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    payload = json.loads(line)
                    return list(payload) if isinstance(payload, dict) else []
        return []
    if suffix == ".json":
        payload = json.loads(path.read_text(encoding="utf-8"))
        return list(payload[0]) if isinstance(payload, list) and payload else []
    delimiter = "\t" if suffix == ".tsv" else ","
    return pacsv.open_csv(
        path,
        read_options=pacsv.ReadOptions(autogenerate_column_names=False),
        parse_options=pacsv.ParseOptions(delimiter=delimiter),
    ).schema.names


def has_structured_choices(columns: list[str]) -> bool:
    """ARC-style records put text and labels inside a choices object."""
    present = set(columns)
    return "choices" in present and "answerKey" in present


def option_fields(columns: list[str]) -> tuple[list[str], str]:
    present = set(columns)
    letters = []
    for offset in range(len(LETTERS)):
        name = f"option_{chr(ord('a') + offset)}"
        if name not in present:
            break
        letters.append(name)
    if len(letters) >= 2:
        return letters, "choices"

    indexed = []
    index = 0
    while f"option_{index}" in present:
        indexed.append(f"option_{index}")
        index += 1
    if len(indexed) >= 2:
        return indexed, "choices"

    numbered = []
    number = 1
    while f"mc_answer{number}" in present:
        numbered.append(f"mc_answer{number}")
        number += 1
    if len(numbered) >= 2:
        return numbered, "choices"

    if "sen" in present and "wrong_sen" in present:
        return ["sen", "wrong_sen"], "pair"

    numbered_choices = []
    number = 1
    while f"choice{number}" in present:
        numbered_choices.append(f"choice{number}")
        number += 1
    if len(numbered_choices) >= 2:
        return numbered_choices, "choices"

    solutions = []
    index = 0
    while f"solution{index}" in present:
        solutions.append(f"solution{index}")
        index += 1
    if len(solutions) >= 2:
        return solutions, "choices"
    return [], ""


def answer_column(columns: list[str], kind: str) -> tuple[str, int]:
    """Return (column, base). Base 1 means the stored number uses 1 for the first choice."""
    if kind == "pair":
        return "", 0
    present = set(columns)
    if "answer_index" in present:
        return "answer_index", 0
    if "correct_answer_num" in present:
        return "correct_answer_num", 1
    if "answer" in present:
        return "answer", 0
    if "label" in present:
        return "label", 0
    return "", 0


def to_index(value, base: int) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value - 1 if base == 1 else value
    if isinstance(value, float) and value.is_integer():
        number = int(value)
        return number - 1 if base == 1 else number
    text = str(value).strip()
    if len(text) == 1 and text.upper() in LETTERS:
        return ord(text.upper()) - ord("A")
    if text.isdigit():
        number = int(text)
        return number - 1 if base == 1 else number
    return None


def drop_trailing_placeholders(choices: list[str], wide: bool) -> list[str]:
    """Drop unused end slots on a wide fixed list such as option_0..option_9.

    A 4-choice item with a blank last choice is a missing choice, so those
    blanks stay in place.
    """
    if not wide:
        return choices
    end = len(choices)
    while end > 2 and (choices[end - 1] == "" or choices[end - 1].casefold() in TRAILING_PLACEHOLDERS):
        end -= 1
    return choices[:end]


def stem_text(record: dict, fields: list[str]) -> str:
    """XCOPA stores the situation in premise and cause/effect in question.
    Global-PIQA stores the situation in prompt."""
    if fields and fields[0].startswith("solution"):
        return stripped(record.get("prompt"))
    if fields and fields[0].startswith("choice") and "premise" in record:
        premise = stripped(record.get("premise"))
        question = stripped(record.get("question")) if "question" in record else ""
        return f"{premise} {question}".strip()
    if "question" in record:
        return stripped(record.get("question"))
    return ""


def expand_choice_struct(records: list[dict]) -> list[dict]:
    """ARC stores choices as {text, label} and a gold key into that label list."""
    if not records:
        return records
    sample = records[0].get("choices")
    if not isinstance(sample, dict) or "text" not in sample:
        return records
    expanded = []
    for record in records:
        choices = record.get("choices") or {}
        texts = list(choices.get("text") or [])
        labels = [stripped(label) for label in (choices.get("label") or [])]
        row = {key: value for key, value in record.items() if key != "choices"}
        for index, text in enumerate(texts):
            row[f"option_{index}"] = text
        key = record.get("answerKey")
        if key is not None and labels:
            key_text = stripped(key)
            if key_text in labels:
                row["answer_index"] = labels.index(key_text)
        expanded.append(row)
    return expanded


def normalize(record: dict, fields: list[str], kind: str, answer_name: str, base: int) -> dict | None:
    if kind == "pair":
        choices = [stripped(record.get("sen")), stripped(record.get("wrong_sen"))]
        return {"question": "", "choices": choices, "answer": 0, "require_stem": False}
    raw = [record.get(field) for field in fields]
    choices = drop_trailing_placeholders([stripped(value) for value in raw], wide=len(fields) > 4)
    if len(choices) < 2:
        return None
    return {
        "question": stem_text(record, fields),
        "choices": choices,
        "answer": to_index(record.get(answer_name), base) if answer_name else None,
        "require_stem": True,
    }


def locate(row: dict) -> dict:
    return {"config": row["config"], "split": row["split"], "row_idx": row["row_idx"], "answer": row["answer"]}


def finding(check: str, severity: str, row: dict, detail: str, rows: list[dict] | None = None) -> dict:
    members = rows if rows is not None else [row]
    record = {
        "check": check,
        "severity": severity,
        "config": row["config"],
        "detail": detail,
        "question": row["question"],
        "choices": list(row["choices"]),
        "rows": [locate(member) for member in members],
    }
    if len(members) == 1:
        record["split"] = row["split"]
        record["row_idx"] = row["row_idx"]
        record["answer"] = row["answer"]
    return record


def key_labeled(stem: str, token: str) -> bool:
    """True when the stem lists this key, or uses it as a name (A, B, C, D)."""
    escaped = re.escape(token.strip())
    # Some stems glue the label to the previous word ("question?a)").
    # A Latin-letter lookaround still ignores "c" inside "technology".
    labeled = rf"(?<![A-Za-z])(?:\({escaped}\)|{escaped}\s*[\.\)．、:：\-])"
    named = rf"(?<![A-Za-z]){escaped}(?![A-Za-z])"
    return re.search(labeled, stem) is not None or re.search(named, stem) is not None


def check_item(row: dict) -> list[dict]:
    hits = []
    question = row["question"]
    choices = list(row["choices"])
    answer = row["answer"]
    require_stem = row["require_stem"]

    if not isinstance(answer, int) or isinstance(answer, bool) or not 0 <= answer < len(choices):
        hits.append(finding("bad_gold_index", "fail", row, f"answer={answer!r}, choices={len(choices)}"))

    for index, choice in enumerate(choices):
        if choice == "":
            hits.append(finding("empty_field", "fail", row, f"choice {index} is empty"))
    if require_stem and question == "":
        hits.append(finding("empty_field", "fail", row, "question is empty"))

    counts = Counter(choice for choice in choices if choice)
    repeated = [text for text, count in counts.items() if count > 1]
    if repeated:
        gold = choices[answer] if isinstance(answer, int) and not isinstance(answer, bool) and 0 <= answer < len(choices) else None
        gold_repeated = gold in repeated
        shown = "; ".join(f"{text[:80]!r} ×{counts[text]}" for text in repeated)
        detail = f"repeated choice text: {shown}"
        if gold_repeated:
            detail += ". The gold choice is one of the repeats."
        hits.append(
            finding(
                "duplicate_gold_choice" if gold_repeated else "duplicate_choice",
                "fail",
                row,
                detail,
            )
        )

    if question:
        for index, choice in enumerate(choices):
            if choice and choice == question:
                hits.append(finding("choice_equals_stem", "fail", row, f"choice {index} equals the question"))

        if choices and all(BARE_KEY.match(choice) for choice in choices):
            missing = []
            for choice in choices:
                parts = [part for part in KEY_PARTS.split(choice) if part]
                unlabeled = [part for part in parts if not key_labeled(question, part)]
                if unlabeled:
                    missing.append(f"{choice} ({', '.join(unlabeled)})")
            if missing:
                hits.append(
                    finding(
                        "unlabeled_choice_keys",
                        "fail",
                        row,
                        "choices are bare keys and the stem does not label them: " + "; ".join(missing),
                    )
                )

        marker = _attachment_hit(question)
        if marker:
            hits.append(finding("missing_attachment", "review", row, f"stem contains {marker!r}"))

    if isinstance(answer, int) and not isinstance(answer, bool) and 0 <= answer < len(choices) and question:
        gold = choices[answer]
        if len(gold) >= GOLD_IN_STEM_MIN_CHARS and len(gold.split()) >= GOLD_IN_STEM_MIN_WORDS:
            if gold.casefold() in question.casefold():
                hits.append(
                    finding(
                        "gold_in_stem",
                        "review",
                        row,
                        f"gold choice appears in the stem: {gold[:80]!r}",
                    )
                )
    return hits


def item_key(row: dict) -> tuple:
    return (row["config"], row["question"], tuple(row["choices"]), row["answer"])


def content_key(row: dict) -> tuple:
    return item_key(row)[:-1]


def check_groups(rows: list[dict]) -> list[dict]:
    hits = []
    by_content: dict[tuple, list[dict]] = defaultdict(list)
    by_item_and_split: dict[tuple, list[dict]] = defaultdict(list)
    by_item: dict[tuple, list[dict]] = defaultdict(list)
    for row in rows:
        by_content[content_key(row)].append(row)
        by_item_and_split[(row["split"], *item_key(row))].append(row)
        by_item[item_key(row)].append(row)

    for group in by_content.values():
        answers = {row["answer"] for row in group}
        if len(group) > 1 and len(answers) > 1:
            shown = ", ".join(str(answer) for answer in sorted(answers, key=lambda value: (value is None, str(value))))
            hits.append(finding("contradictory_gold", "fail", group[0], f"same stem and choices, gold indexes {shown}", group))

    for group in by_item_and_split.values():
        if len(group) > 1:
            hits.append(
                finding(
                    "duplicate_in_split",
                    "fail",
                    group[0],
                    f"{len(group)} exact copies in {group[0]['split']}",
                    group,
                )
            )

    for group in by_item.values():
        splits = {row["split"] for row in group}
        if len(splits) > 1:
            hits.append(
                finding(
                    "overlap_across_splits",
                    "review",
                    group[0],
                    "exact copy in " + " and ".join(sorted(splits)),
                    group,
                )
            )
    return hits


def load_dataset(root: Path) -> tuple[list[dict], str, int]:
    rows: list[dict] = []
    schema = ""
    skipped = 0
    for path in data_files(root):
        columns = columns_of(path)
        fields, kind = option_fields(columns)
        if not fields and not has_structured_choices(columns):
            skipped += 1
            continue
        records = expand_choice_struct(read_records(path))
        if not records:
            skipped += 1
            continue
        columns = list(records[0].keys())
        fields, kind = option_fields(columns)
        if not fields:
            skipped += 1
            continue
        answer_name, base = answer_column(columns, kind)
        if not schema:
            schema = f"{kind}, choices={len(fields)} ({fields[0]}..{fields[-1]}), answer={answer_name or 'pair'} base={base}"
        config = path.stem if path.parent.resolve() == root.resolve() or path.parent.name.lower() == "data" else path.parent.name
        split = split_of(path)
        for row_idx, record in enumerate(records):
            normalized = normalize(record, fields, kind, answer_name, base)
            if normalized is None:
                continue
            normalized["config"] = config
            normalized["split"] = split
            normalized["row_idx"] = row_idx
            rows.append(normalized)
    return rows, schema, skipped


def write_findings(path: Path, hits: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(hit, ensure_ascii=False) + "\n" for hit in hits), encoding="utf-8")


def summarize(name: str, rows: list[dict], hits: list[dict]) -> None:
    print(f"\n{name}: rows {len(rows)}  findings {len(hits)}")
    counts = Counter((hit["severity"], hit["check"]) for hit in hits)
    if not counts:
        print("  no findings")
        return
    for (severity, check), count in sorted(counts.items(), key=lambda item: (item[0][0], item[0][1])):
        print(f"  {count:7d}  {severity:6s}  {check}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("datasets", nargs="+", type=Path, help="directories of parquet, csv/tsv, or jsonl files")
    parser.add_argument("--out-dir", type=Path, default=Path("mcq-checks"))
    args = parser.parse_args()

    for root in args.datasets:
        rows, schema, skipped = load_dataset(root)
        if not schema:
            print(f"\n{root}: skipped, not MCQ ({skipped} files)")
            continue
        print(f"\n{root}: {schema}")
        if skipped:
            print(f"  skipped {skipped} files with no choice columns")
        hits = [hit for row in rows for hit in check_item(row)]
        hits.extend(check_groups(rows))
        hits.sort(key=lambda hit: (hit["check"], hit["config"], hit["rows"][0]["split"], hit["rows"][0]["row_idx"]))
        out = args.out_dir / f"{root.name}.jsonl"
        write_findings(out, hits)
        summarize(root.name, rows, hits)
        print(f"  written {out}")


if __name__ == "__main__":
    main()
