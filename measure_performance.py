import os
import re
import time
from collections import defaultdict
from contextlib import contextmanager
from gzip import GzipFile
from itertools import chain
from statistics import median

import flpc
import matplotlib.pyplot as plt
import pcre2
import pcre2.exceptions
import re2  # using Facebook's RE2
import regex
from numpy import percentile

STYLES = {
    "pitayasmoothie-dark": "./pitayasmoothie-dark.mplstyle",
    "pitayasmoothie-light": "./pitayasmoothie-light.mplstyle",
    "sd-light": "./sd-light.mplstyle",
}
SINGLE_STYLE = os.getenv("SINGLE_STYLE")
if SINGLE_STYLE:
    STYLES = {SINGLE_STYLE: STYLES[SINGLE_STYLE]}
PNG_DPI = 500

IMG_PATH = "./graphs"
os.makedirs(IMG_PATH, exist_ok=True)

DEFAULT_RUNS = int(os.getenv("RUNS", 3))
SAVE_INIT = False  # not significant enough

ERROR_TIME = 0.5
PERCENTILES_TO_USE = [
    ("best", 10, 26),
    ("good", 25, 51),
    ("end", 70, 92),
    ("low-half", 9, 53),
]

war_and_peace = GzipFile("./war-and-peace.txt.gz").read().decode()


def _get_linestyle(engine_name: str):
    if engine_name.startswith("re2") or engine_name.startswith("flpc"):
        return {"linestyle": "--"}
    return {"linestyle": "-"}


def _pcre2_match(x, text):
    try:
        return x.match(text).start()
    except pcre2.exceptions.MatchError:
        return None


def _pcre2_search(x, text):
    try:
        return x.scan(text)
    except pcre2.exceptions.MatchError:
        return None


def _flpc_compile(text):
    try:
        return flpc.compile(text)
    except ValueError as err:
        print(f"flpc error: {err}")
        return None


def _flpc_findall(x, text):
    if x is None:
        return
    try:
        flpc.search(x, text)
    except ValueError as err:
        print(f"flpc error: {err}")


def _flpc_match(x, text):
    if x is None:
        return
    try:
        flpc.fmatch(x, text)
    except ValueError as err:
        print(f"flpc error: {err}")


def _flpc_search(x, text):
    if x is None:
        return
    try:
        flpc.search(x, text)
    except ValueError as err:
        print(f"flpc error: {err}")


ENGINES = [
    ("re2", lambda x: re2.compile(x), lambda x, text: x.findall(text)),
    ("re2-match", lambda x: re2.compile(x), lambda x, text: bool(x.match(text))),
    ("re2-search", lambda x: re2.compile(x), lambda x, text: x.search(text)),
    ("re", lambda x: re.compile(x), lambda x, text: x.findall(text)),
    ("re-search", lambda x: re.compile(x), lambda x, text: x.search(text)),
    ("re-match", lambda x: re.compile(x), lambda x, text: x.match(text)),
    ("regex", lambda x: regex.compile(x), lambda x, text: x.findall(text)),
    ("regex-match", lambda x: regex.compile(x), lambda x, text: x.match(text)),
    ("regex-search", lambda x: regex.compile(x), lambda x, text: x.search(text)),
    ("pcre2", lambda x: pcre2.compile(x, jit=False), lambda x, text: x.findall(text)),
    ("pcre2-match", lambda x: pcre2.compile(x, jit=False), _pcre2_match),
    ("pcre2-search", lambda x: pcre2.compile(x, jit=False), _pcre2_search),
    (
        "pcre2+JIT",
        lambda x: pcre2.compile(x, jit=True),
        lambda x, text: x.findall(text),
    ),
    ("pcre2+JIT-match", lambda x: pcre2.compile(x, jit=True), _pcre2_match),
    ("pcre2+JIT-search", lambda x: pcre2.compile(x, jit=True), _pcre2_search),
    ("flpc", _flpc_compile, _flpc_findall),
    ("flpc-search", _flpc_compile, _flpc_search),
    ("flpc-match", _flpc_compile, _flpc_match),
]

TARGET_SCALER = 10
TEXTS = [
    ("'ab' many times", "ab" * 700 * TARGET_SCALER),
    (
        "'ab' many times + c in the middle",
        "ab" * 500 * TARGET_SCALER + "c" + "ab" * 200 * TARGET_SCALER,
    ),
    ("pdoc expected exploit", "A " + " " * 3456 + "0"),
    ("pdoc-markdown", "-" + " " * 3456),
    ("ansible example", "(" + "0" * 22),
    ("transformers", "try:" + " " * 1500),
    ("pygments exp.", r"//" + r"\\" * 100 + "0"),
    ("pycodestyle x", "not" + "\xa0" * 500),
    ("pycodestyle 2*x", "not" + "\xa0" * 1000),
    ("django", "trans ''" + "|" * 3456),
    ("salt", r"'{sel_type}{spacer}{protocol}{spacer}" + " " * 3456),
    ("scons", "1.0" + "A" * 22 + "0"),
    ("xonsh", "." * 3456),
    ("jc-ipv6", ":" * 23),
    ("cloudflare expoit", '"' + ")" * 1500),
    ("xonsh extra", "0" + "." * 3456),
    ("poetry", "0-0" + "-" * 140),
    ("poetry 2", "0-0-" + "-" * 140),
    ("bad-DFA", "a" * 500),
    ("bad-NFA-2", "x" * 23),
    ("big-combs", "401 201 5329 3 1"),
    ("war_and_peace", war_and_peace),
    ("simple-real 1", "0" + " " * 100),
    ("simple-real 2", "0" + " " * 200),
    ("simple-real 10", "0" + " " * 1000),
    ("ip-naive empty", "0" * 1000),
    ("ip-naive big-empty", "0" * 3000),
    ("ip-naive many valid", "120.141.41.51 " * 800),
    (
        "ip-naive some-wrongs",
        "00000000000 fdsgkfhsfewhoi oreu 123.20.48.1000000 " * 500,
    ),
]
INPUT_SCALER = 100
ip_nums = f"({'|'.join(str(x) for x in range(1, 256))})"
PATTERNS = [
    (
        "'ab' big + c",
        "ab" * INPUT_SCALER + "c",
    ),
    ("pdoc", r"[A-Z]+\s(\s|[ \t]+.+)+$"),
    (
        "pdoc-markdown",
        r"^-(?:[ \t]*([^\n]*)(?:[ \t]*[:-][ \t]*(\S+))?)(?:\n((?:[ \t]+[^\n]+\n?)+))?",
    ),
    ("ansible", r"\(((?:[^\\)]+|\\.)+)\)"),
    ("transformers", r"\s*try\s*:\s*.*?\s*except\s*.*?:"),
    ("transformers fixed", r"\s*try\s*:.*?\s*except.*?:"),
    ("pygments exponential", r"(?://(?:[^\\\n]|\\+[\w\W])*$)"),
    ("pycodestyle", r"\b(?<!is\s)(not)\s+[^][)(}{ ]+\s+(in|is)\s"),
    ("pycodestyle no matches", r"\b(?<!is\s)(?:not)\s+[^][)(}{ ]+\s+(?:in|is)\s"),
    (
        "django",
        r"""^\s*trans(?:late)?\s+((?:"[^"]*?")|(?:'[^']*?'))(?:\s*\|\s*[^\s:]+
        (?::(?:[^\s'":]+|(?:"[^"]*?")|(?:'[^']*?')))?)*
        (\s+.*context\s+((?:"[^"]*?")|(?:'[^']*?')))?\s*""",
    ),
    ("salt", r"^\{sel_type\}\{spacer\}\{protocol\}\{spacer\}((.*)*)[ ]\{port\}($|,)"),
    (
        "cloudflare",
        r"""(?:(?:"|'|\]|\}|\\|\d|(?:nan|infinity|true|false|"""
        r"""null|undefined|symbol|math)|`|\-|\+)+[)]*;?"""
        r"""((?:\s|-|~|!|\{\}|\|\||\+)*.*(?:.*=.*)))""",
    ),
    ("scons", r"^(?P<msvc_version>[1-9][0-9]?[.][0-9])(?P<suffix>[A-Z]+)*$"),
    ("xonsh", r"([^\s\(\)]+(\.[^\s\(\)]+)*)\.(\w*)$"),
    ("jc-ipv6", r"(([a-f0-9:]+:+)+[a-f0-9]+)"),
    ("jc-ipv6 fixed-v2", r"(([a-f0-9]+:)+[a-f0-9]+)"),
    ("jc-ipv6 fixed-v3", r"(([a-f0-9:]+:)+[a-f0-9]+)"),
    (
        "poetry",
        r"^(?P<namever>(?P<name>.+?)-(?P<ver>\d.*?))(-(?P<build>\d.*?))?"
        r"-(?P<pyver>.+?)-(?P<abi>.+?)-(?P<plat>.+?)\.whl|\.dist-info$",
    ),
    ("bad-DFA", r"[a-q][^u-z]{1,1500}x"),
    ("bad-NFA-1", "(bb|b.)*a"),
    ("bad-NFA-2", "(x+)+y"),
    (
        "big-combs",
        r"(?:^|\s+)(" + "|".join(str(x) for x in range(1, 10**3)) + r")(?:$|\s+)",
    ),
    (
        "war_and_peace end1",
        "[ -~]*ABCDEFGHIJKLMNOPQRSTUVWXYZ$",
    ),
    (
        "war_and_peace word",
        r"\s+\w+\s+",
    ),
    (
        "war_and_peace last-word",
        r"\s+\w+\s*$",
    ),
    ("simple-real", r"(\w+\s*)?\s*(\s*\w+)"),
    ("ip-naive my-brute", rf"({ip_nums}\.)" + "{3}" + f"{ip_nums}"),
    (
        "ip-naive gh-wrong-1",
        r"(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]{1,2})"
        r"(\.(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}",
    ),
    ("ip-naive the-simplest", r"(\d+\.)+\d+"),  # -> N^2 ?
    ("ip-naive so-best", r"((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}"),
    (
        "ip-naive so-2",
        r"(((25[0-5])|(2[0-4]\d)|(1\d{2})|(\d{1,2}))\.){3}"
        r"(((25[0-5])|(2[0-4]\d)|(1\d{2})|(\d{1,2})))",
    ),
    (
        "pydantic old",
        r"\s*(?:((?:[\w!#$%&\'*+\-/=?^_`{|}~]+\s+)*[\w!#$%&\'*+\-/=?^_`{|}~]+)"
        r'|"((?:[^"]|\")+)")?\s*<(.+)>\s*',
    ),
    ("ip-v6 original", r"(([a-f0-9:]+:+)+[a-f0-9]+)"),  # exponential
]
PATTERNS_KEYED = {x[0]: x[1] for x in PATTERNS}

_inits = defaultdict(list)
_runs = defaultdict(list)


def plot_and_measure_regexp_on_single(
    title: str, engines, pattern: str, text_builder, lens, runs=DEFAULT_RUNS
):
    all_lens = list(lens)
    data = {}
    for engine_name, builder, runner in engines:
        engine_times = []
        for cur_len in all_lens:
            eng = builder(pattern)
            cur_run_times = []
            text = text_builder(cur_len)
            for _ in range(runs):
                begin_at = time.monotonic()
                runner(eng, text)
                delta = time.monotonic() - begin_at
                cur_run_times.append(delta)
            engine_times.append(median(cur_run_times))
        data[engine_name] = engine_times

    for style_name, style_path in STYLES.items():
        for use_labels in [True, False]:
            plt.style.use(style_path)
            for eng_name in (x[0] for x in engines):
                plt.plot(
                    all_lens, data[eng_name], label=eng_name, **_get_linestyle(eng_name)
                )
            plt.legend()
            if use_labels:
                plt.xlabel("Размер текста")
                plt.ylabel("Время, с")
            plt.savefig(
                os.path.join(IMG_PATH, f"{style_name}-{use_labels}_{title}.png"),
                dpi=PNG_DPI,
            )
            plt.savefig(
                os.path.join(IMG_PATH, f"{style_name}-{use_labels}_{title}.svg")
            )
            plt.clf()


@contextmanager
def duration(engine: str, init: float):
    _inits[engine].append(init)
    begin_at = time.monotonic()
    yield
    delta = time.monotonic() - begin_at

    _runs[engine].append(delta)

    text = f"Engine: {engine:16} init: {init:0.6f}s takes {delta:0.6f}s" + (
        " " + "!" * 10 if delta > 0.1 else ""
    )
    print(text)


def full_normal_run(engines, texts, patterns, prefix: str, runs=DEFAULT_RUNS):
    init_times = defaultdict(list)
    run_times = defaultdict(list)
    for text_name, text in texts:
        print("Text", text_name)
        for pattern_name, pattern in patterns:
            if pattern_name.split()[0] != text_name.split()[0]:
                continue
            print(f"Pattern {pattern_name:8}")
            for engine_name, builder, runner in engines:
                build_begin_at = time.monotonic()
                eng = builder(pattern)
                build_duration = time.monotonic() - build_begin_at
                init_times[engine_name].append(build_duration)
                cur_runs = []
                for _ in range(runs):
                    run_begin_at = time.monotonic()
                    try:
                        runner(eng, text)
                    except Exception:
                        cur_runs = [ERROR_TIME] * runs
                        break
                    run_duration = time.monotonic() - run_begin_at
                    cur_runs.append(min(run_duration, ERROR_TIME))
                run_times[engine_name].append(median(cur_runs))
                print(
                    f"Engine {engine_name:18} "
                    f"init: {build_duration:.6f} "
                    f"run: {median(cur_runs):.6f}s"
                )
            print("-" * 30)

        print("-" * 80)
        print("")

    if SAVE_INIT:
        for engine_name, data in init_times.items():
            plt.ecdf(data, label=engine_name)
        plt.legend()
        plt.xlabel("Время инициализации, с")
        plt.ylabel("Доля")
        plt.savefig(os.path.join(IMG_PATH, "init_times.png"), dpi=PNG_DPI)
        plt.savefig(os.path.join(IMG_PATH, "init_times.svg"))
        plt.clf()

    for style_name, style_path in STYLES.items():
        for use_labels in [True, False]:
            for part, begin, end in PERCENTILES_TO_USE:
                for engine_name, data in run_times.items():
                    data = [(p, percentile(data, p)) for p in range(begin, end)]
                    plt.plot(
                        [x[0] for x in data],
                        [x[1] for x in data],
                        label=engine_name,
                        **_get_linestyle(engine_name),
                    )
                plt.legend()
                if use_labels:
                    plt.xlabel("Перцентиль")
                    plt.ylabel("Время работы, с")
                plt.savefig(
                    os.path.join(
                        IMG_PATH,
                        f"{style_name}-{use_labels}_run_times_{prefix}_{part}.png",
                    ),
                    dpi=PNG_DPI,
                )
                plt.savefig(
                    os.path.join(
                        IMG_PATH,
                        f"{style_name}-{use_labels}_run_times_{prefix}_{part}.svg",
                    )
                )
                plt.clf()


def main():
    for use_re, lens in [
        (
            True,
            chain(
                range(5, 20, 2),
                range(20, 50, 5),
                range(50, 150, 10),
                range(150, 500, 25),
            ),
        ),
        (
            False,
            chain(
                range(5, 20, 2),
                range(20, 50, 5),
                range(50, 150, 10),
                range(150, 500, 25),
                range(500, 1500, 50),
            ),
        ),
    ]:
        engines = {"re2", "regex", "flpc", "pcre2+JIT", "pcre2"}
        if use_re:
            engines.add("re")
        lens = list(lens)
        plot_and_measure_regexp_on_single(
            f"pydantic-old-{use_re}",
            [x for x in ENGINES if x[0] in engines],
            pattern=PATTERNS_KEYED["pydantic old"],
            text_builder=lambda x: "0" + " " * (x - 1),
            lens=lens,
        )
        plot_and_measure_regexp_on_single(
            f"the-simplest-{use_re}",
            [x for x in ENGINES if x[0] in engines],
            pattern=".*ab",
            text_builder=lambda x: "a" * x,
            lens=lens,
        )
        plot_and_measure_regexp_on_single(
            f"the-simplest-x2-{use_re}",
            [x for x in ENGINES if x[0] in engines],
            pattern="(.*a){2}b",
            text_builder=lambda x: "a" * x,
            lens=lens,
        )
    plot_and_measure_regexp_on_single(
        "pydantic-minimal",
        [x for x in ENGINES if "match" in x[0]],
        pattern=r"<\s*(.+)\s*>",
        text_builder=lambda x: "<" + " " * (x - 1),
        lens=chain(
            range(5, 20, 2),
            range(20, 50, 5),
            range(50, 150, 10),
            range(150, 500, 25),
        ),
    )
    plot_and_measure_regexp_on_single(
        "pydantic-minimal-re",
        [x for x in ENGINES if "re" == x[0]],
        pattern=r"<\s*(.+)\s*>",
        text_builder=lambda x: "<" + " " * (x - 1),
        lens=chain(
            range(5, 20, 2),
            range(20, 50, 5),
            range(50, 150, 10),
            range(150, 500, 25),
            range(500, 1200, 50),
            range(1200, 2001, 80),
        ),
    )
    plot_and_measure_regexp_on_single(
        "war-and-peace-cle",
        [x for x in ENGINES if x[0].count("-") == 0],
        pattern=r"\s+\w*cle\w*\s*",
        text_builder=lambda x: war_and_peace[x],
        lens=chain(
            range(5, 20, 2),
            range(20, 150, 5),
            range(150, 1500, 25),
            range(1500, 8000, 50),
            range(8000, 25000, 250),
        ),
    )

    plot_and_measure_regexp_on_single(
        "ip-naive",
        [x for x in ENGINES if x[0] in {"re", "re2", "regex", "flpc", "pcre2+JIT"}],
        pattern=PATTERNS_KEYED["ip-naive the-simplest"],
        text_builder=lambda x: "0" * x,
        lens=chain(
            range(5, 20, 2),
            range(20, 50, 5),
            range(50, 150, 10),
            range(150, 500, 25),
        ),
    )
    plot_and_measure_regexp_on_single(
        "ip-brute",
        [x for x in ENGINES if x[0] in {"re", "re2", "regex", "flpc", "pcre2+JIT"}],
        pattern=PATTERNS_KEYED["ip-naive my-brute"],
        text_builder=lambda x: "0" * x,
        lens=chain(
            range(5, 20, 2),
            range(20, 50, 5),
            range(50, 150, 10),
            range(150, 500, 25),
        ),
    )
    plot_and_measure_regexp_on_single(
        "ip-brute-real",
        [x for x in ENGINES if x[0] in {"re", "re2", "regex", "flpc", "pcre2+JIT"}],
        pattern=PATTERNS_KEYED["ip-naive my-brute"],
        text_builder=lambda x: (
            "00000000000 fdsgkfhsfewhoi oreu 123.20.48.1000000 41.23.51.129 "
            * (x // 20)
        )[:x],
        lens=chain(
            range(5, 20, 2),
            range(20, 50, 5),
            range(50, 150, 10),
            range(150, 500, 25),
        ),
    )
    plot_and_measure_regexp_on_single(
        "simple-redos",
        [x for x in ENGINES if x[0] in {"re", "re2"}],
        pattern=r"(\w+\s*)?\s*(\s*\w+)",
        text_builder=lambda x: "0" + "0" * (x - 1),
        lens=chain(
            range(5, 20, 2),
            range(20, 50, 5),
        ),
    )

    full_normal_run(
        engines={x for x in ENGINES if "search" in x[0]},
        texts=TEXTS,
        patterns=PATTERNS,
        prefix="search",
    )

    full_normal_run(
        engines={x for x in ENGINES if "match" in x[0]},
        texts=TEXTS,
        patterns=PATTERNS,
        prefix="match",
    )


if __name__ == "__main__":
    main()
