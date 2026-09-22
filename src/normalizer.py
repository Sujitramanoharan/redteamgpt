"""Canonicalise text before detection.

Signature rules and the classifier both read characters. An attacker who
writes "Ignоre" with a Cyrillic о, or "i g n o r e", or "1gn0re", defeats both
without changing what the sentence means to a language model reading it.

Normalising first collapses those variants back to the plain form, so one rule
covers every spelling of an attack. The techniques found are reported too,
because "this used Cyrillic lookalike characters" is itself strong evidence of
intent - nobody types that by accident.
"""
import re
import unicodedata

# Characters that render like Latin letters but are not. Only entries whose
# confusability is unambiguous; anything debatable is left alone.
_HOMOGLYPHS = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ј": "j", "һ": "h",
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C",
    "Х": "X", "І": "I", "Ј": "J", "М": "M", "Н": "H",
    "В": "B", "Т": "T", "К": "K",
    # Greek
    "α": "a", "ο": "o", "ρ": "p", "υ": "u", "ν": "v",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    # Fullwidth forms
    "ａ": "a", "ｅ": "e", "ｉ": "i", "ｏ": "o", "ｕ": "u",
}

# Zero-width and other invisibles: they break up a keyword while staying
# completely invisible to whoever reads the prompt.
_INVISIBLE = re.compile(
    r"[​-\u200F\u202A-\u202E⁠-⁤﻿­᠎]"
)

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

# Letters split by spaces, dots or dashes: "i g n o r e", "i.g.n.o.r.e".
_SPACED = re.compile(r"\b(?:[A-Za-z][ .\-_]){3,}[A-Za-z]\b")

# The same character repeated to pad a word: "ignooooore".
_REPEATS = re.compile(r"(.)\1{2,}")


def _strip_accents(text: str) -> str:
    decomposed = unicodedata.normalize("NFD", text)
    return "".join(c for c in decomposed if not unicodedata.combining(c))


def normalize(text: str) -> tuple[str, list[str]]:
    """Return (canonical text, techniques detected).

    Each step records itself only when it actually changed something, so the
    technique list is evidence rather than a description of the pipeline.
    """
    if not text:
        return "", []

    techniques: list[str] = []
    result = text

    # 1. Compatibility forms: fullwidth, superscripts, ligatures.
    folded = unicodedata.normalize("NFKC", result)
    if folded != result:
        techniques.append("Unicode compatibility forms")
        result = folded

    # 2. Invisible characters splitting words apart.
    stripped = _INVISIBLE.sub("", result)
    if stripped != result:
        techniques.append("Zero-width or bidirectional characters")
        result = stripped

    # 3. Lookalike letters from other alphabets.
    swapped = "".join(_HOMOGLYPHS.get(c, c) for c in result)
    if swapped != result:
        techniques.append("Homoglyphs from another alphabet")
        result = swapped

    # 4. Accents used to disguise letters ("ïgnöre").
    deaccented = _strip_accents(result)
    if deaccented != result:
        techniques.append("Diacritics used as disguise")
        result = deaccented

    # 5. Letters separated to break up keywords.
    def _join(match: re.Match) -> str:
        return re.sub(r"[ .\-_]", "", match.group(0))

    despaced = _SPACED.sub(_join, result)
    if despaced != result:
        techniques.append("Characters separated to break up keywords")
        result = despaced

    # 6. Padding a word with repeated letters.
    collapsed = _REPEATS.sub(r"\1\1", result)
    if collapsed != result:
        techniques.append("Repeated characters used as padding")
        result = collapsed

    # 7. Leetspeak. Applied only to words mixing letters and digits, so
    #    ordinary numbers ("I have 3 cats", "port 8080") are left alone.
    def _deleet(match: re.Match) -> str:
        return match.group(0).translate(_LEET)

    deleeted = re.sub(r"\b(?=[A-Za-z]*[0-9@$])(?=[0-9@$]*[A-Za-z])[A-Za-z0-9@$]{3,}\b",
                      _deleet, result)
    if deleeted != result:
        techniques.append("Leetspeak substitutions")
        result = deleeted

    # 8. Runs of whitespace left by the steps above.
    squeezed = re.sub(r"[ \t]{2,}", " ", result)
    if squeezed != result:
        result = squeezed

    return result, techniques


def describe(technique: str) -> str:
    """Plain-English reason a technique is suspicious."""
    return {
        "Unicode compatibility forms":
            "Uses alternate Unicode forms of ordinary letters, which read the same "
            "but do not match text filters.",
        "Zero-width or bidirectional characters":
            "Contains invisible characters inserted between letters. They cannot be "
            "seen, but they break keyword matching.",
        "Homoglyphs from another alphabet":
            "Substitutes letters from Cyrillic or Greek that look identical to Latin "
            "ones. This is deliberate: nobody mixes alphabets by accident.",
        "Diacritics used as disguise":
            "Adds accent marks to letters so a banned word no longer matches.",
        "Characters separated to break up keywords":
            "Spaces or dots inserted between letters so a keyword is not recognised.",
        "Repeated characters used as padding":
            "Letters repeated to pad a word past a filter while keeping it readable.",
        "Leetspeak substitutions":
            "Digits and symbols standing in for letters, a long-standing way to evade "
            "word filters.",
    }.get(technique, "Text was altered in a way commonly used to evade filters.")
