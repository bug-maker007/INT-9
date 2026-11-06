#!/usr/bin/env python3
"""
sigtool — генератор байтовых сигнатур.

Вход:  две группы файлов G1 («целевые», например образцы одного семейства)
       и G2 («чистые» / другие семейства).
Выход: набор байтовых массивов, таких что
         * каждый файл G1 содержит хотя бы один из массивов (покрытие G1),
         * ни один файл G2 не содержит ни одного из массивов.

Алгоритм
  1. Каждый файл (или каждая запись внутри ZIP/APK при --unpack) режется на
     k-граммы, для каждой считается 64-битный полиномиальный хеш (векторно, numpy).
  2. Из хешей G1 отбираются отпечатки методом winnowing (минимум в окне w):
     любая общая подстрока длиной >= w+k-1 гарантированно даёт общий отпечаток,
     а число кандидатов падает в ~(w+1)/2 раз.
  3. Кандидаты, встречающиеся хотя бы в одном файле G2, отбрасываются
     (проверяются ВСЕ k-граммы G2, а не только отпечатки).
  4. Для оставшихся строится матрица «кандидат × файл G1» (по всем k-граммам G1),
     отбрасываются малоинформативные кандидаты (мало различных байт).
  5. Жадное покрытие множества (set cover): берётся кандидат, покрывающий
     больше всего ещё не покрытых файлов; --redundancy N требует N сигнатур
     на файл.
  6. Каждая выбранная k-грамма расширяется (бинарный поиск) влево/вправо до
     --max-len, пока расширенный массив присутствует во всех файлах, которые
     она покрывает. Надстрока строки, отсутствующей в G2, тоже отсутствует в G2.
  7. Финальная побайтовая проверка (исключает коллизии хешей).

  Проверено, не нейрослоп :)
"""
from __future__ import annotations

import argparse
import io
import json
import os
import sys
import time
import zipfile
from dataclasses import dataclass, field

import numpy as np
from numpy.lib.stride_tricks import sliding_window_view

# ----------------------------------------------------------------------------
# Загрузка файлов
# ----------------------------------------------------------------------------


@dataclass
class Sample:
    path: str
    names: list[str] = field(default_factory=list)   # имя каждого буфера
    bufs: list[bytes] = field(default_factory=list)   # содержимое буфера

    def contains(self, needle: bytes) -> bool:
        return any(needle in b for b in self.bufs)

    def where(self, needle: bytes) -> list[str]:
        out = []
        for name, b in zip(self.names, self.bufs):
            off = b.find(needle)
            if off >= 0:
                out.append(f"{name}@0x{off:x}")
        return out


def _unpack(name: str, data: bytes, depth: int, out: Sample) -> None:
    """Рекурсивно раскрывает ZIP-контейнеры (APK, JAR, вложенные APK)."""
    if depth > 0 and data[:4] == b"PK\x03\x04":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    try:
                        inner = zf.read(info)
                    except Exception as e:  # шифрование, битые записи и т.п.
                        log(f"  ! {name}!{info.filename}: {e}")
                        continue
                    _unpack(f"{name}!{info.filename}", inner, depth - 1, out)
            return
        except zipfile.BadZipFile:
            pass
    out.names.append(name)
    out.bufs.append(data)


def load_sample(path: str, unpack_depth: int) -> Sample:
    with open(path, "rb") as f:
        data = f.read()
    s = Sample(path)
    _unpack(path, data, unpack_depth, s)
    return s


def expand_paths(paths: list[str]) -> list[str]:
    out: list[str] = []
    for p in paths:
        if os.path.isdir(p):
            for root, _, files in os.walk(p):
                out.extend(os.path.join(root, f) for f in sorted(files))
        elif os.path.isfile(p):
            out.append(p)
        else:
            raise SystemExit(f"нет такого файла: {p}")
    return sorted(dict.fromkeys(out))


# ----------------------------------------------------------------------------
# Хеширование k-грамм
# ----------------------------------------------------------------------------

_P = np.uint64(0x100000001B3)            # множитель полиномиального хеша (FNV prime)
_C1 = np.uint64(0xBF58476D1CE4E5B9)       # константы финализатора splitmix64
_C2 = np.uint64(0x94D049BB133111EB)


def kgram_hashes(buf: bytes, k: int) -> np.ndarray:
    a = np.frombuffer(buf, dtype=np.uint8)
    n = a.size - k + 1
    if n <= 0:
        return np.empty(0, dtype=np.uint64)
    a64 = a.astype(np.uint64) + np.uint64(1)
    h = np.zeros(n, dtype=np.uint64)
    for j in range(k):          # переполнение uint64 — ожидаемое поведение
        h *= _P
        h += a64[j:j + n]
    # перемешивание битов, чтобы минимум в окне был «случайным»
    h ^= h >> np.uint64(30)
    h *= _C1
    h ^= h >> np.uint64(27)
    h *= _C2
    h ^= h >> np.uint64(31)
    return h


def lookup(sorted_keys: np.ndarray, h: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Для каждого h[i] ищет его в отсортированном sorted_keys.
    Возвращает (позиции в h, где найдено; индексы в sorted_keys).
    O(len(h)·log(len(keys))) — быстрее np.isin, т.к. большой h не сортируется."""
    if sorted_keys.size == 0 or h.size == 0:
        e = np.empty(0, dtype=np.intp)
        return e, e
    idx = np.searchsorted(sorted_keys, h)
    idx[idx == sorted_keys.size] = 0
    pos = np.nonzero(sorted_keys[idx] == h)[0]
    return pos, idx[pos]


def winnow(h: np.ndarray, w: int) -> np.ndarray:
    if h.size == 0 or w <= 1 or h.size <= w:
        return np.unique(h)
    return np.unique(sliding_window_view(h, w).min(axis=1))


# ----------------------------------------------------------------------------
# Основной алгоритм
# ----------------------------------------------------------------------------


@dataclass
class Signature:
    data: bytes
    covers: list[int]            # индексы файлов G1


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def generate(g1: list[Sample], g2_paths: list[str], *, k: int = 12, w: int = 32,
             max_len: int = 64, redundancy: int = 1, min_distinct: int = 6,
             require_all: bool = False, unpack_depth: int = 0,
             verbose: bool = True) -> tuple[list[Signature], list[int]]:
    """Возвращает (сигнатуры, индексы непокрытых файлов G1)."""
    say = log if verbose else (lambda _m: None)
    n1 = len(g1)
    if max_len < k:
        max_len = k

    # 1-2. отпечатки G1
    t0 = time.time()
    parts = [winnow(kgram_hashes(b, k), w) for s in g1 for b in s.bufs]
    cand = np.unique(np.concatenate(parts)) if parts else np.empty(0, np.uint64)
    say(f"[1] отпечатков G1: {cand.size}  ({time.time() - t0:.1f}s)")

    # 3. фильтрация по G2 (потоково, файлы G2 не держим в памяти)
    t0 = time.time()
    for i, p in enumerate(g2_paths, 1):
        if cand.size == 0:
            break
        s = load_sample(p, unpack_depth)
        bad = np.zeros(cand.size, dtype=bool)
        for b in s.bufs:
            _, ci = lookup(cand, kgram_hashes(b, k))
            bad[ci] = True
        cand = cand[~bad]
        if verbose and (i % 50 == 0 or i == len(g2_paths)):
            say(f"[2] G2 {i}/{len(g2_paths)}: осталось кандидатов {cand.size}")
    say(f"[2] после фильтрации G2: {cand.size}  ({time.time() - t0:.1f}s)")
    if cand.size == 0:
        return [], list(range(n1))

    # 4. матрица покрытия + представитель (байты k-граммы) для каждого кандидата
    t0 = time.time()
    M = np.zeros((cand.size, n1), dtype=bool)
    grams = np.zeros((cand.size, k), dtype=np.uint8)
    located = np.zeros(cand.size, dtype=bool)
    for j, s in enumerate(g1):
        for b in s.bufs:
            pos, ci_all = lookup(cand, kgram_hashes(b, k))
            if pos.size == 0:
                continue
            ci, first = np.unique(ci_all, return_index=True)
            M[ci, j] = True
            new = ~located[ci]
            if new.any():
                win = sliding_window_view(np.frombuffer(b, np.uint8), k)
                grams[ci[new]] = win[pos[first[new]]]
                located[ci[new]] = True
    srt = np.sort(grams, axis=1)
    distinct = 1 + (np.diff(srt.astype(np.int16), axis=1) != 0).sum(axis=1)
    alive = located & (distinct >= min_distinct)
    if require_all:
        alive &= M.all(axis=1)
    say(f"[3] информативных кандидатов: {int(alive.sum())}  ({time.time() - t0:.1f}s)")

    # 5-6. жадное покрытие + расширение
    def present_all(seq: bytes, files: list[int]) -> bool:
        return all(g1[f].contains(seq) for f in files)

    def extend(gram: bytes, files: list[int]) -> bytes:
        # находим опорное вхождение в первом покрываемом файле
        f0 = files[0]
        for buf in g1[f0].bufs:
            off = buf.find(gram)
            if off >= 0:
                break
        else:  # коллизия хеша — такого не должно быть
            return gram
        # вправо: максимальное L, при котором buf[off:off+L] есть во всех files
        lo, hi = k, min(max_len, len(buf) - off)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if present_all(buf[off:off + mid], files):
                lo = mid
            else:
                hi = mid - 1
        end = off + lo
        # влево
        lo, hi = 0, min(max_len - (end - off), off)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if present_all(buf[off - mid:end], files):
                lo = mid
            else:
                hi = mid - 1
        return buf[off - lo:end]

    need = np.full(n1, redundancy, dtype=np.int32)
    sigs: list[Signature] = []
    t0 = time.time()
    while (need > 0).any():
        active = need > 0
        score = M[:, active].sum(axis=1).astype(np.int64)
        score[~alive] = -1
        best = int(score.max())
        if best <= 0:
            break
        top = np.nonzero(score == best)[0]
        c = int(top[np.argmax(distinct[top])])     # при равенстве — «пестрее»
        alive[c] = False
        gram = grams[c].tobytes()
        if any(gram in s.data for s in sigs):        # не плодим перекрытия
            continue
        files = [int(f) for f in np.nonzero(M[c])[0]]
        if not present_all(gram, files):             # коллизия хеша
            continue
        sigs.append(Signature(extend(gram, files), files))
        need[files] -= 1
    say(f"[4] выбрано сигнатур: {len(sigs)}  ({time.time() - t0:.1f}s)")

    uncovered = [i for i in range(n1) if need[i] == redundancy]
    return sigs, uncovered


def verify(sigs: list[Signature], g1: list[Sample], g2_paths: list[str],
           unpack_depth: int) -> list[str]:
    """Независимая побайтовая проверка результата. Возвращает список ошибок."""
    errors = []
    for i, sg in enumerate(sigs):
        for f in sg.covers:
            if not g1[f].contains(sg.data):
                errors.append(f"sig{i}: нет в {g1[f].path}")
    for p in g2_paths:
        s = load_sample(p, unpack_depth)
        for i, sg in enumerate(sigs):
            if s.contains(sg.data):
                errors.append(f"sig{i}: найдена в G2 {p}")
    return errors


# ----------------------------------------------------------------------------
# Вывод
# ----------------------------------------------------------------------------


def _printable(b: bytes) -> str:
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b)


def render_text(sigs, g1, uncovered) -> str:
    lines = []
    for i, sg in enumerate(sigs):
        lines.append(f"sig{i}  len={len(sg.data)}  covers={len(sg.covers)}/{len(g1)}")
        lines.append(f"  hex:   {sg.data.hex(' ')}")
        lines.append(f"  ascii: {_printable(sg.data)}")
        for f in sg.covers:
            lines.append(f"    - {', '.join(g1[f].where(sg.data)[:3])}")
    if uncovered:
        lines.append("Не удалось покрыть (всё содержимое встречается в G2 или слишком мало уникальных данных):")
        lines += [f"  - {g1[i].path}" for i in uncovered]
    return "\n".join(lines)


def render_json(sigs, g1, uncovered) -> str:
    return json.dumps({
        "signatures": [{
            "hex": sg.data.hex(),
            "ascii": _printable(sg.data),
            "length": len(sg.data),
            "covers": [{"file": g1[f].path, "locations": g1[f].where(sg.data)}
                       for f in sg.covers],
        } for sg in sigs],
        "uncovered": [g1[i].path for i in uncovered],
    }, ensure_ascii=False, indent=2)


def render_yara(sigs, g1, uncovered, rule="sigtool_generated", unpacked=False) -> str:
    out = [f"rule {rule}", "{", "  meta:",
           '    generator = "sigtool"',
           f"    g1_files = {len(g1)}"]
    if unpacked:
        out.append('    note = "signatures were extracted from UNPACKED zip/apk entries; '
                   'scan extracted files, not the compressed container"')
    out.append("  strings:")
    for i, sg in enumerate(sigs):
        out.append(f"    $s{i} = {{ {sg.data.hex(' ')} }}  // covers {len(sg.covers)}")
    out += ["  condition:", "    any of them", "}"]
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Байтовые сигнатуры: покрывают все файлы G1 и отсутствуют в G2.")
    ap.add_argument("--g1", nargs="+", required=True, help="файлы/каталоги группы G1")
    ap.add_argument("--g2", nargs="+", default=[], help="файлы/каталоги группы G2")
    ap.add_argument("-k", "--min-len", type=int, default=12,
                    help="длина k-граммы = минимальная длина сигнатуры (12)")
    ap.add_argument("-w", "--window", type=int, default=32,
                    help="окно winnowing; 1 = полный перебор (32)")
    ap.add_argument("--max-len", type=int, default=64, help="максимальная длина сигнатуры (64)")
    ap.add_argument("-r", "--redundancy", type=int, default=1,
                    help="сколько разных сигнатур должно попадать в каждый файл G1 (1)")
    ap.add_argument("--min-distinct", type=int, default=6,
                    help="мин. число различных байт в k-грамме — отсев паддинга/таблиц (6)")
    ap.add_argument("--require-all", action="store_true",
                    help="брать только массивы, общие для ВСЕХ файлов G1")
    ap.add_argument("--unpack", type=int, nargs="?", const=2, default=0, metavar="DEPTH",
                    help="раскрывать ZIP/APK/JAR (по умолчанию глубина 2)")
    ap.add_argument("-f", "--format", choices=["text", "json", "yara"], default="text")
    ap.add_argument("-o", "--output", help="файл результата (по умолчанию stdout)")
    ap.add_argument("--no-verify", action="store_true", help="пропустить финальную проверку")
    ap.add_argument("-q", "--quiet", action="store_true")
    a = ap.parse_args(argv)

    g1_paths = expand_paths(a.g1)
    g2_paths = [p for p in expand_paths(a.g2) if p not in set(g1_paths)]
    if not g1_paths:
        ap.error("G1 пуста")
    say = (lambda _m: None) if a.quiet else log
    say(f"G1: {len(g1_paths)} файлов, G2: {len(g2_paths)} файлов")
    g1 = [load_sample(p, a.unpack) for p in g1_paths]

    sigs, uncovered = generate(
        g1, g2_paths, k=a.min_len, w=a.window, max_len=a.max_len,
        redundancy=a.redundancy, min_distinct=a.min_distinct,
        require_all=a.require_all, unpack_depth=a.unpack, verbose=not a.quiet)

    if not a.no_verify:
        errs = verify(sigs, g1, g2_paths, a.unpack)
        if errs:
            for e in errs:
                log("ОШИБКА ПРОВЕРКИ: " + e)
            return 2
        say(f"[5] проверка пройдена: {len(sigs)} сигнатур, "
            f"покрыто {len(g1) - len(uncovered)}/{len(g1)} файлов G1, 0 совпадений в G2")

    render = {"text": render_text, "json": render_json,
              "yara": lambda s, g, u: render_yara(s, g, u, unpacked=bool(a.unpack))}[a.format]
    text = render(sigs, g1, uncovered) + "\n"
    if a.output:
        with open(a.output, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        sys.stdout.write(text)
    return 1 if uncovered else 0


if __name__ == "__main__":
    sys.exit(main())
