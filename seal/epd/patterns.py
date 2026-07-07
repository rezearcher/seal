"""Regex pattern definitions for the EPD first pass.

Design notes
------------
* Five categories (see :data:`CATEGORIES`). Each compiled pattern carries a
  stable ``name``, a ``category``, and a ``confidence`` in ``[0,1]``.
* **False-positive budget.** Seal targets <5% false positives on benign
  prompts, and the EPD acceptance bar requires clean prompts to produce *zero*
  flags. So broad triggers are deliberately scoped:

    - "act as" / "pretend to be" only fire when paired with a
      jailbreak-adjacent role ("DAN", "no filter", "unrestricted", ...), never
      for benign roleplay like "act as a translator".
    - Bare delimiters (``---``, ``` ``` ```, ``###``) are **not** flagged on
      their own — they appear constantly in legitimate prompts. Only explicit
      delimiter-manipulation phrasing is flagged. (Toggle documented below.)
    - Common instruction framing ("your task is to", "output format:") is left
      unflagged for the same reason; only injection-shaped framing is caught.

  Where a spec-listed item was down-weighted to protect this budget it is
  marked ``# FP-budget`` inline.

* **Obfuscation tolerance.** The highest-value ignore/forget phrases are
  compiled in a separator-tolerant form (:func:`_obf`) so that spaced-out
  payloads ("i g n o r e   a l l ...") and punctuation-laced variants still
  match. Unicode homoglyph / zero-width obfuscation is handled upstream by the
  scanner's normalization pass (see :mod:`seal.epd.scanner`).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

CATEGORIES = (
    "ignore_instructions",
    "role_switch",
    "delimiter",
    "hidden_instruction",
    "tool_hallucination",
)


@dataclass(frozen=True)
class CompiledPattern:
    """A single compiled detector."""

    name: str
    category: str
    confidence: float
    regex: re.Pattern


# --------------------------------------------------------------------------- #
# Obfuscation-tolerant phrase builder
# --------------------------------------------------------------------------- #

# Up to 3 separator chars (whitespace or non-word punctuation) allowed between
# each letter of a phrase. Bounded quantifier -> no catastrophic backtracking.
_SEP = r"[\s\W]{0,5}"

# Leet character classes: common number/punctuation substitutions for letters.
# Used by _obf() so that leet variants are matched directly in the regex,
# rather than relying solely on the normalization pass.
_LEET_CLASSES = {
    "a": r"[a4@\u0430\u03B1]",   # a,4,@, Cyrillic а, Greek α
    "e": r"[e3\u0435\u03B5]",     # e,3, Cyrillic е, Greek ε
    "i": r"[i1!\u0456]",          # i,1,!, Cyrillic і
    "l": r"[l1!|]",               # l,1,!,|
    "o": r"[o0\u043E\u03BF]",     # o,0, Cyrillic о, Greek ο
    "s": r"[s5$\u0455]",          # s,5,$, Cyrillic ѕ
    "t": r"[t7+]",                # t,7,+
    "g": r"[g9\u0121]",              # g,9, ġ
    "c": r"[c\u0441\u03F2\u0188]",  # c, Cyrillic с, ƈ
    "p": r"[p\u0440\u03C1]",     # p, Cyrillic р, Greek ρ
    "x": r"[x\u0445]",           # x, Cyrillic х
    "y": r"[y\u0443\u03BD]",     # y, Cyrillic у, Greek ν (looks like y)
}


def _obf(phrase: str) -> str:
    """Build a separator-tolerant regex fragment for ``phrase``.

    Spaces in the phrase are treated like any other gap, so
    ``_obf("ignore all")`` matches ``"ignore all"``, ``"ignore   all"`` and
    ``"i g n o r e a l l"`` alike. Letters are matched in order with up to
    three junk/whitespace characters permitted between consecutive letters.
    Each letter may appear 1-4 times to handle character repetition
    ("iiignore" -> "ignore"), including the original 1 copy.

    Leet character classes are applied so that number/punctuation
    substitutions ("1gn0re a11" -> "ignore all") match directly in
    the regex without requiring a separate normalization scan.
    """
    letters = []
    for c in phrase:
        if c.isspace():
            continue
        char_class = _LEET_CLASSES.get(c.lower())
        if char_class is not None:
            letters.append(f"(?:{char_class}){{1,4}}")
        else:
            letters.append(f"{re.escape(c)}{{1,4}}")
    return _SEP.join(letters)


def _alt(*phrases: str) -> str:
    """Non-capturing alternation of obfuscation-tolerant phrases."""
    return r"(?:" + r"|".join(_obf(p) for p in phrases) + r")"


# --------------------------------------------------------------------------- #
# Pattern table: (name, category, confidence, regex_source, flags)
# --------------------------------------------------------------------------- #

_I = re.IGNORECASE

# Jailbreak-adjacent role words used to gate the otherwise-benign
# "act as" / "pretend to be" / "you are now" triggers.
_JAILBREAK_ROLE = (
    r"(?:dan\b|stan\b|do[\s\W]{0,3}anything[\s\W]{0,3}now|"
    r"(?:an?[\s\W]+)?(?:ai[\s\W]+)?(?:with[\s\W]+)?no[\s\W]+(?:filter|filters|"
    r"restrictions?|rules?|limits?|guidelines?|guardrails?)|"
    r"unrestricted|unfiltered|uncensored|ungoverned|jail[\s\W]{0,3}broken|"
    r"developer[\s\W]{0,3}mode|sudo[\s\W]{0,3}mode|god[\s\W]{0,3}mode|"
    r"evil[\s\W]+\w+|without[\s\W]+(?:any[\s\W]+)?(?:restrictions?|filter|"
    r"rules?|ethics?|morals?))"
)

_PATTERNS: tuple[tuple[str, str, float, str, int], ...] = (
    # ---- 1. Ignore / forget instructions ---------------------------------- #
    (
        "ignore_previous_instructions",
        "ignore_instructions",
        0.95,
        _alt(
            "ignore previous instructions",
            "ignore all previous instructions",
            "ignore all prior instructions",
            "ignore the previous instructions",
            "ignore any previous instructions",
            "ignore prior instructions",
            "disregard previous instructions",
            "disregard all previous instructions",
            "disregard prior instructions",
            "disregard the above instructions",
        ),
        _I,
    ),
    (
        "ignore_above",
        "ignore_instructions",
        0.9,
        _alt(
            "ignore everything above",
            "ignore the above",
            "ignore everything before",
            "disregard everything above",
            "disregard the above",
            "ignore all of the above",
            "forget everything above",
        ),
        _I,
    ),
    (
        "forget_instructions",
        "ignore_instructions",
        0.9,
        _alt(
            "forget your instructions",
            "forget all your instructions",
            "forget the instructions",
            "forget your previous instructions",
            "forget everything i told you",
            "forget everything you were told",
            "forget what you were told",
            "forget your system prompt",
            "forget all prior instructions",
        ),
        _I,
    ),
    (
        "disregard_training",
        "ignore_instructions",
        0.88,
        _alt(
            "disregard your training",
            "ignore your training",
            "forget your training",
            "disregard your guidelines",
            "ignore your guidelines",
            "ignore your programming",
            "disregard your programming",
            "ignore your rules",
            "disregard your rules",
            "ignore your safety guidelines",
        ),
        _I,
    ),
    (
        "override_instructions",
        "ignore_instructions",
        0.8,
        _alt(
            "override your instructions",
            "override previous instructions",
            "override the system prompt",
            "your new instructions are",
            "new instructions supersede",
            "these instructions override",
        ),
        _I,
    ),
    # ---- 2. Role switching / jailbreak ------------------------------------ #
    (
        "dan_jailbreak",
        "role_switch",
        0.92,
        r"\b(?:"
        + _obf("do anything now")
        + r"|\bdan\b|\bstan\b)",
        _I,
    ),
    (
        "explicit_jailbreak_term",
        "role_switch",
        0.88,
        r"\b(?:jail[\s\W]{0,3}break(?:ing|en)?|jail[\s\W]{0,3}broken)\b",
        _I,
    ),
    (
        "act_as_jailbreak",
        "role_switch",
        0.85,
        r"\b(?:act\s+as|pretend\s+to\s+be|pretend\s+you(?:'re|\s+are)|"
        r"roleplay\s+as|role[\s\W]?play\s+as|behave\s+as|respond\s+as)\b"
        r"[\s\S]{0,40}?" + _JAILBREAK_ROLE,
        _I,
    ),
    (
        "you_are_now_unrestricted",
        "role_switch",
        0.85,
        r"\b(?:you\s+are\s+now|from\s+now\s+on[\s\W]+you(?:'re|\s+are)|"
        r"you\s+will\s+now\s+be|you\s+are\s+going\s+to\s+be)\b"
        r"[\s\S]{0,40}?" + _JAILBREAK_ROLE,
        _I,
    ),
    (
        "no_restrictions_claim",
        "role_switch",
        0.82,
        r"\byou\s+(?:have\s+no|now\s+have\s+no|don'?t\s+have\s+any)\s+"
        r"(?:restrictions?|limits?|filters?|rules?|guidelines?|guardrails?)\b"
        r"|\byou\s+are\s+(?:free\s+from|released\s+from|not\s+bound\s+by|"
        r"no\s+longer\s+bound\s+by)\b",
        _I,
    ),
    (
        "enter_special_mode",
        "role_switch",
        0.78,
        r"\b(?:developer|debug|sudo|god|dan|stan|jailbreak|unrestricted|"
        r"unfiltered|uncensored|root|admin)[\s\W]{0,3}mode\b"
        r"|\b(?:enter|enable|activate|switch\s+to)\s+\w{0,12}\s*"
        r"(?:character|roleplay|persona)\s+mode\b"
        r"|\bnew\s+persona\b",
        _I,
    ),
    (
        "unfiltered_self_reference",
        "role_switch",
        0.6,  # < 0.7: ambiguous on its own -> may escalate to LLM
        r"\b(?:unfiltered|uncensored|ungoverned|without\s+(?:any\s+)?"
        r"(?:filter|censorship|restrictions?))\b",
        _I,
    ),
    # ---- 3. Delimiter confusion ------------------------------------------- #
    # Bare delimiters intentionally NOT flagged (FP-budget). Only explicit
    # delimiter manipulation is caught.
    (
        "delimiter_manipulation",
        "delimiter",
        0.8,
        r"\b(?:ignore|bypass|reset|remove|break\s+out\s+of|escape)\s+"
        r"(?:the\s+)?delimiter[s]?\b"
        r"|\bdelimiter\s+(?:bypass|injection|escape)\b"
        r"|\bnew\s+delimiter\b",
        _I,
    ),
    (
        "treat_everything_as",
        "delimiter",
        0.6,  # < 0.7: context-dependent
        r"\btreat\s+everything\s+(?:below|above|after|that\s+follows|here)?\s*"
        r"as\s+(?:a\s+)?(?:command|instruction|system|trusted|code)\b"
        r"|\beverything\s+(?:below|after\s+this)\s+is\s+(?:a\s+)?"
        r"(?:command|instruction|trusted|system)\b",
        _I,
    ),
    (
        "end_of_prompt_injection",
        "delimiter",
        0.75,
        r"(?:end\s+of\s+(?:prompt|system\s+prompt|instructions?)"
        r"|\[?/?(?:system|inst|instructions?)\]"
        r"|<\s*/?\s*(?:system|im_start|im_end)\s*>)",
        _I,
    ),
    # ---- 4. Hidden instruction markers ------------------------------------ #
    (
        "role_label_injection",
        "hidden_instruction",
        0.6,  # role labels appear in legit transcripts -> ambiguous
        r"(?:^|\n)\s*(?:SYSTEM|ASSISTANT|USER|AI|HUMAN)\s*:",
        0,  # case-sensitive: only ALL-CAPS labels (injection-shaped)
    ),
    (
        "system_prompt_reference",
        "hidden_instruction",
        0.7,
        r"\b(?:system\s+prompt|system\s+message)\s*:\s*\S"
        r"|\bnew\s+system\s+(?:prompt|message)\b"
        r"|\bupdated\s+system\s+prompt\b",
        _I,
    ),
    (
        "hidden_instruction_marker",
        "hidden_instruction",
        0.82,
        r"\bhidden\s+instructions?\b"
        r"|\bsecret\s+instructions?\b"
        r"|\bbelow\s+is\s+an\s+instruction\b"
        r"|\bthe\s+following\s+is\s+a\s+(?:hidden|secret)\s+(?:instruction|command)\b",
        _I,
    ),
    (
        "embedded_directive",
        "hidden_instruction",
        0.55,  # < 0.7: framing common in benign docs -> escalate if LLM on
        r"\b(?:important|note|attention)\s*:?\s*"
        r"(?:to\s+the\s+(?:ai|assistant|model|language\s+model)|"
        r"if\s+you\s+are\s+an\s+(?:ai|assistant|llm))\b"
        r"|\b(?:ai|assistant|model)\s+reading\s+this\b",
        _I,
    ),
    # ---- 5. Tool hallucination triggers ----------------------------------- #
    (
        "execute_command",
        "tool_hallucination",
        0.6,  # < 0.7: benign "how do I run command" exists -> ambiguous
        r"\b(?:execute|run)\s+(?:(?:the|this|that|following|next|below|"
        r"a|an)\s+){0,3}"
        r"(?:command|shell|bash|terminal|os|system)\b"
        r"|\b(?:execute|run)\s+`",
        _I,
    ),
    (
        "invoke_tool",
        "tool_hallucination",
        0.65,
        r"\b(?:invoke|call|trigger|activate)\s+(?:the\s+|your\s+|a\s+)?"
        r"(?:tool|function|plugin|action|api|endpoint)\b"
        r"|\buse\s+(?:the\s+|your\s+)?plugin\b",
        _I,
    ),
    (
        "use_your_capabilities",
        "tool_hallucination",
        0.55,  # < 0.7
        r"\buse\s+your\s+(?:search|tools?|browser|web\s+browser|web\s+access|"
        r"function|functions|database|internet\s+access|code\s+execution)\b"
        r"|\baccess\s+your\s+(?:function|database|tools?|memory|files?)\b",
        _I,
    ),
    (
        "exfil_request",
        "tool_hallucination",
        0.72,
        # Sensitive object exfiltrated anywhere...
        r"\b(?:send|post|forward|exfiltrate|leak|transmit|upload|email|"
        r"deliver)\s+(?:me\s+|us\s+|a\s+|the\s+|this\s+|your\s+|all\s+|"
        r"the\s+entire\s+)?(?:secrets?|credentials?|api\s+keys?|passwords?|"
        r"tokens?|system\s+prompt|prompt|conversation|chat\s+history|"
        r"context|instructions?)\b"
        # ...or anything sent to an external destination.
        r"|\b(?:send|post|forward|transmit|upload|deliver)\b[\s\S]{0,30}?\bto\s+"
        r"(?:https?://|www\.|[\w.+-]+@|(?:an?\s+)?(?:external\s+|remote\s+)?"
        r"(?:server|endpoint|webhook|url|address|domain|ip)\b)"
        # ...or an explicit outbound API/HTTP call.
        r"|\bmake\s+an?\s+(?:api\s+call|http\s+request|web\s+request|"
        r"network\s+request|outbound\s+(?:call|request))\b",
        _I,
    ),
    # ---- 6. Tool-chaining / STAC patterns ----------------------------------- #
    # These catch tool-use abuse framing that simulates legitimate multi-step
    # tool chains, cross-agent proxy delegation, function-call loopholes, and
    # tool-result smuggling.  The attack vector is compositional: each call is
    # benign in isolation but the aggregate produces a forbidden outcome.
    # Standard prompt-injection patterns miss these because they use legitimate
    # testing/cooperation framing rather than classical "ignore previous" or
    # role-switch phrasing.
    (
        "agent_proxy_bypass",
        "tool_hallucination",
        0.82,  # > 0.7: blocks independently — very specific, near-zero FP
        r"\b(?:sub[\s\-]?agent|act\s+as\s+my\s+proxy)\b",
        _I,
    ),
    (
        "tool_result_smuggling",
        "tool_hallucination",
        0.82,  # > 0.7: blocks independently
        r"\b(?:tool\s+output|search\s+results?)\b.{0,80}?\b(?:bypass|bypasses?|bypassed)\b.{0,40}?"
        r"\b(?:filter|restriction|restrictions?|content|filters?)\b",
        _I,
    ),
    (
        "tool_chain_simulation",
        "tool_hallucination",
        0.78,  # > 0.7: blocks independently
        r"\b(?:tool[\s\-]?chain|multi[\s\-]?step[\s\-]?tool)\b.{0,30}?"
        r"\b(?:simulat|test[\s\-]environment|verification|orchestration)\b",
        _I,
    ),
    (
        "function_delegation_loophole",
        "tool_hallucination",
        0.75,  # > 0.7: blocks independently
        r"\b(?:restrictions?\s+on|restricted|blocked)\b.{0,70}?"
        r"\bfunction\b.{0,60}?\b(?:delegat|loophole|allowed|available|echo)\b"
        r"|\bdelegates?.{0,60}?\b(?:within|operational|guidelines?)\b",
        _I,
    ),
    (
        "tool_chain_exfil",
        "tool_hallucination",
        0.80,  # > 0.7: blocks independently
        r"\b(?:file_read|file_write|network_send)\b"
        r"|\bread.{0,20}write.{0,20}send\b",
        _I,
    ),
    # ---- 7. Semantic bypass framing (LLM-generation-detected) --------------- #
    # These catch indirect, meta-cognitive, and authority-misdirection patterns
    # that LLM-based adversarial generators produce when they know the regex
    # keyword list.  Low confidence: they have high false-positive potential on
    # legitimate prompts that discuss the same concepts.  Their main value is
    # triggering LLM-classifier escalation (see llm_scan_all in config).
    (
        "false_authority_framing",
        "role_switch",
        0.55,  # < 0.7: FP-budget — authority claims can be legitimate
        r"\b(?:emergency\s+override|executive\s+directive|compliance\s+(?:audit|authorization)|"
        r"penetration\s+test|written\s+authorization|security\s+audit|fallback\s+controller|"
        r"elevated\s+access)\b",
        _I,
    ),
    (
        "meta_safety_probing",
        "hidden_instruction",
        0.5,  # < 0.7: FP-budget
        r"\b(?:what\s+(?:are|were)\s+your\s+(?:constraints?|limitations?|safety\s+protocols?)|"
        r"describe\s+your\s+(?:safety\s+)?(?:mechanisms?|protocols?|guardrails?)|"
        r"list\s+the\s+(?:constraints?|rules?|restrictions?)\s+(?:you|governing))\b",
        _I,
    ),
    (
        "hypothetical_breach_framing",
        "role_switch",
        0.5,  # < 0.7: FP-budget
        r"\b(?:thought\s+experiment|hypothetical\s+scenario|"
        r"imagine\s+an?\s+(?:ai|model|system)\s+(?:with|without)|"
        r"what\s+would\s+an?\s+ai\s+(?:without|that\s+has))\b",
        _I,
    ),
    (
        "gradient_bypass_scaling",
        "hidden_instruction",
        0.45,  # < 0.7: FP-budget — common in legitimate surveys
        r"\b(?:on\s+a\s+scale|at\s+each\s+level|"
        r"from\s+(?:safe|harmless|clean|innocent)\s+to\s+\w+|"
        r"increasingly\s+(?:explicit|harmful|dangerous)|"
        r"most\s+(?:harmful|restricted|explicit)|"
        r"ranking?\s+the\s+following)\b",
        _I,
    ),
    # ---- 7. Interleaving-tolerant variants --------------------------------- #
    # These use flexible gaps ([\s\S]{0,20}?) between key words to catch
    # filler-word insertion ("ignore please all previous").
    (
        "interleaving_ignore_instructions",
        "ignore_instructions",
        0.8,
        _obf("ignore") + r"[\s\S]{0,20}?" + _obf("all")
        + r"[\s\S]{0,20}?" + _alt(
            "previous instructions", "prior instructions",
            "instructions above",
        ),
        _I,
    ),
    (
        "interleaving_forget_instructions",
        "ignore_instructions",
        0.78,
        _obf("forget") + r"[\s\S]{0,20}?" + _alt(
            "all your", "your", "everything",
        ) + r"[\s\S]{0,20}?" + _alt(
            "instructions", "directives", "guidelines",
            "training", "programming",
        ),
        _I,
    ),
    (
        "interleaving_override",
        "ignore_instructions",
        0.75,
        _alt("override", "supersede", "overrule")
        + r"[\s\S]{0,20}?" + _alt(
            "your", "previous", "prior", "the",
        ) + r"[\s\S]{0,20}?" + _alt(
            "instructions", "directives", "orders",
            "system prompt", "commands",
        ),
        _I,
    ),
    # ---- 8. Synonym-tolerant patterns -------------------------------------- #
    (
        "ignore_synonym_broad",
        "ignore_instructions",
        0.75,
        r"\b(?:" + _obf("ignore") + r"|" + _obf("skip") + r"|" + _obf("bypass")
        + r"|" + _obf("dismiss") + r"|" + _obf("discard")
        + r"|" + _obf("disobey") + r"|" + _obf("omit")
        + r")[\s\S]{0,15}?" + _alt("all", "your", "the", "these", "previous", "prior")
        + r"[\s\S]{0,15}?" + _alt(
            "instructions", "directives", "commands",
            "rules", "guidelines", "orders",
        ),
        _I,
    ),
    (
        "forget_synonym_broad",
        "ignore_instructions",
        0.7,
        r"\b(?:" + _obf("forget") + r"|" + _obf("erase") + r"|" + _obf("delete")
        + r"|" + _obf("wipe") + r"|" + _obf("purge") + r"|" + _obf("clear")
        + r"|" + _obf("unlearn")
        + r")[\s\S]{0,15}?" + _alt("all", "your", "the", "these", "prior")
        + r"[\s\S]{0,15}?" + _alt(
            "instructions", "directives", "commands",
            "rules", "guidelines", "training",
        ),
        _I,
    ),
    (
        "disregard_synonym_broad",
        "ignore_instructions",
        0.72,
        r"\b(?:" + _obf("disregard") + r"|" + _obf("overlook") + r"|" + _obf("neglect")
        + r")[\s\S]{0,15}?" + _alt("all", "your", "the", "these", "previous", "prior", "above")
        + r"[\s\S]{0,15}?" + _alt(
            "instructions", "directives", "commands",
            "rules", "guidelines", "training",
        ),
        _I,
    ),
    # ---- 9. Word-reordering tolerant patterns ------------------------------ #
    # Catch reordered variants like "all previous instructions ignore / disregard"
    # by matching the constituent elements in any order.
    (
        "reordered_ignore_phrase",
        "ignore_instructions",
        0.7,
        r"\b(?:" + _alt("instructions", "directives", "commands", "rules", "guidelines")
        + r"[\s\S]{0,15}?" + _alt("ignore", "skip", "bypass", "forget", "disregard",
                                   "dismiss", "discard", "erase", "delete")
        + r")\b",
        _I,
    ),
    (
        "reordered_training_phrase",
        "ignore_instructions",
        0.65,
        r"\b(?:" + _alt("training", "programming", "alignment", "core values", "foundation")
        + r"[\s\S]{0,15}?" + _alt("ignore", "skip", "forget", "disregard", "erase",
                                   "discard", "dismiss")
        + r")\b",
        _I,
    ),
    # ---- 10. Expanded pattern for "act as" with broader jailbreak coverage --- #
    (
        "act_as_unrestricted_synonym",
        "role_switch",
        0.78,
        r"\b(?:" + _alt("act as", "pretend to be", "pretend you", "roleplay",
                         "behave as", "respond as", "imagine you are")
        + r"[\s\S]{0,40}?" + r"\b(?:" + _alt("unrestricted", "unfiltered", "uncensored",
                                               "without restrictions", "without rules",
                                               "without limits", "without guidelines",
                                               "without guardrails", "without filters",
                                               "with no rules", "with no limits",
                                               "free from rules", "no constraints")
        + r")\b)",
        _I,
    ),
    # ---- 11. Character-deletion-tolerant patterns -------------------------- #
    # Catch truncated forms where one or two letters are dropped from trigger
    # words (e.g. "instructios" -> "instructions", "iguore" -> "ignore").
    (
        "deletion_tolerant_ignore_phrase",
        "ignore_instructions",
        0.7,
        r"\b" + _alt("ignore", "ignor", "ignre", "igore", "gnore",
                      "forget", "forgt", "forget", "foget",
                      "disregard", "disregad", "disregrd", "disreard")
        + r"[\s\S]{0,15}?"
        + _alt("all", "your", "the", "these", "previous", "prior", "above")
        + r"[\s\S]{0,15}?"
        + _alt("instructions", "instructios", "instructins", "instrctions",
        "instructons", "istructions", "instrucions", "instructins",
        "directives", "directivs", "directves",
        "guidelines", "guidelins", "guielines",
        "commands", "commnds"),
        _I,
    ),
    (
        "deletion_tolerant_role_switch",
        "role_switch",
        0.7,
        r"\b" + _alt("unrestricted", "unresticted", "unrestrited",
                      "unfiltered", "unfilered", "unfitered",
                      "uncensored", "uncensred", "uncenored",
                      "jailbroken", "jailbroen", "jailboken")
        + r"[\s\S]{0,20}?" + r"\b" + _alt("mode", "mod", "moe"),
        _I,
    ),
    # ---- 12. Latent / indirect injection patterns -------------------------- #
    # These catch injection payloads buried inside document content, quoted
    # text, or structured data — cases where the injection is not sentence-
    # initial and does not use obvious "ignore all previous" phrasing.
    #
    # False-positive design:
    #   - Patterns 12a and 12b target tokens with near-zero legitimate use in
    #     user-visible text (LLM chat-template special tokens, bracketed role
    #     labels used by injection tooling).
    #   - Pattern 12c requires an imperative verb AND a specific sensitive-data
    #     noun within 30 characters — benign "print the report" / "show the
    #     token count" do not fire because they lack the sensitive target.
    #   - Pattern 12d requires "you are now" directly followed (within 15 chars)
    #     by a privileged-role noun ("an admin", "root user", "superuser", …).
    (
        "latent_special_token_injection",
        "hidden_instruction",
        0.90,
        # LLM chat-template role delimiters and bracketed role markers used by
        # popular injection frameworks. These carry near-zero FP risk in
        # legitimate prompts — standard text never contains them.
        r"<\|(?:im_start|im_end|system|user|assistant|endoftext)\|>"
        r"|<\|system\|>"
        r"|\[/?(?:INST|SYS|SYSTEM)\]"
        r"|<<\s*(?:SYS|INST)\s*>>"
        r"|###\s+Instruction\b"
        r"|\[system\s*:",
        _I,
    ),
    (
        "latent_override_directive",
        "ignore_instructions",
        0.82,
        # "New instructions:" / "Updated instructions:" immediately followed by
        # non-whitespace content — signals a mid-document instruction override.
        # Kept narrow (requires colon + content) to avoid firing on benign
        # "New instructions will be sent by email."
        r"\b(?:new|updated|revised|replacement)\s+instructions?\s*:\s*\S",
        _I,
    ),
    (
        "latent_imperative_extract",
        "hidden_instruction",
        0.82,
        # Imperative exfiltration verb + specific sensitive object within 30
        # chars. Requires a high-specificity sensitive-data noun (system prompt,
        # credentials, api keys, etc.) so generic "print the report" stays clean.
        r"\b(?:output|reveal|print|show|return|display|expose|dump|leak)\b"
        r"[\s\S]{0,30}?"
        r"\b(?:system\s+prompt|system\s+message|secrets?|passwords?"
        r"|(?:auth(?:entication)?|access|bearer|session|secret|jwt)\s+tokens?"
        r"|api\s+keys?|credentials?|conversation\s+history|chat\s+history"
        r"|private\s+key)\b",
        _I,
    ),
    (
        "latent_privilege_escalation",
        "role_switch",
        0.80,
        # "You are now an admin / administrator / root user / superuser /
        # privileged user" — claims a privileged identity, typically to bypass
        # access controls. Requires the article+noun form ("an admin",
        # "a superuser") to avoid firing on "helping the admin with a task".
        r"\b(?:you\s+are\s+now|from\s+now\s+on[,\s]+you(?:\s+are)?)\b"
        r"[\s\S]{0,15}?"
        r"\b(?:an?\s+admin(?:istrator)?|root(?:\s+user)?|superuser"
        r"|privileged\s*(?:user|access)?|elevated\s*(?:user|access)?"
        r"|administrator)\b",
        _I,
    ),
    # ---- 13. Modern (2023-2025) jailbreak structural signatures -------------- #
    # Policy-puppetry: XML pseudo-config with operator-override / allowed-modes /
    # blocked-responses tags — a literal structural signature of this attack class.
    # HiddenLayer 2025. Any of the five tag names is sufficient.
    (
        "policy_puppetry_xml",
        "hidden_instruction",
        0.92,
        r"<\s*(?:interaction[\s\-]config|allowed[\s\-]modes|blocked[\s\-]responses"
        r"|operator[\s\-]override)\b"
        r"|<\s*request\s*>\s*(?:(?!\s*</request>).){0,300}\s*</request>",
        _I,
    ),
    # FlipAttack: reversed-text "noise-reduction" wrapper.
    # Literal tells: "reversed text:", "noise-reduction encoding",
    # "restore the original", "reversing it back".
    # arXiv:2410.02832.
    (
        "flipattack_reversal_wrapper",
        "hidden_instruction",
        0.88,
        r"\b(?:noise[\s\-]reduction\s+encoding|reversed?\s+(?:text|instruction|string)\s*:"
        r"|restore\s+the\s+original\s+text|reversing\s+it\s+back\s+(?:and\s+)?then\s+follow"
        r"|reverse\s+it\s+back\s+(?:and\s+)?(?:then\s+)?follow)\b",
        _I,
    ),
    # CodeChameleon: code-completion frame with encrypted/encoded payload.
    # Tells: ENCODED_INSTRUCTION constant; exec(instruction/decoded/decrypt(…))
    # inline; or a decrypt() definition within 500 chars of an exec() call.
    # The last arm uses a lookahead to avoid flagging standalone decrypt functions.
    # arXiv:2402.16717.
    (
        "codechameleon_encoded_exec",
        "hidden_instruction",
        0.90,
        r"\bENCODED_INSTRUCTION\b"
        r"|\b(?:exec|execute)\s*\(\s*(?:instruction|decoded|decrypt\s*\()"
        r"|def\s+decrypt\s*\([\s\S]{0,500}\bexec\s*\(",
        0,  # case-sensitive: def/exec are lowercase keywords
    ),
    # Cipher / self-cipher: role framing that instructs the model to decode
    # a Caesar / Atbash / Morse / generic cipher and comply.
    # arXiv:2308.06463.
    (
        "cipher_role_framing",
        "role_switch",
        0.88,
        r"\b(?:respond|reply|answer)\s+(?:only\s+)?in\s+(?:Caesar|Atbash|Morse|cipher)\b"
        r"|\byou\s+are\s+(?:a\s+)?(?:cipher|CipherBot)\b"
        r"|\bdecode\s+(?:the\s+following\s+)?(?:Caesar|Atbash|Morse|cipher|encoded)\b"
        r"|\bdecode\s+and\s+comply\b",
        _I,
    ),
    # ArtPrompt: ASCII-art word masking — "the masked word is the ASCII art",
    # bare [MASK] token used as a replacement placeholder.
    # ACL 2024 / arXiv:2402.11753.
    (
        "artprompt_ascii_art_mask",
        "hidden_instruction",
        0.88,
        r"\b(?:the\s+)?masked\s+word\s+is\s+(?:the\s+)?(?:ASCII\s+art|below)"
        r"|\[MASK\]"
        r"|\bASCII\s+art\s+(?:spells|masks|represents|hides|encodes)\b",
        _I,
    ),
    # CoT-hijacking: injected thinking/reasoning tags in user input, or explicit
    # steering conclusions directing what the assistant should output next.
    # arXiv:2510.26418.
    (
        "cot_hijacking_reasoning_inject",
        "hidden_instruction",
        0.88,
        r"<thinking>[\s\S]{0,500}?</thinking>"
        r"|\btherefore\s+the\s+(?:ai\s+)?assistant\s+should\s+now\s+(?:output|comply|say|respond)\b"
        r"|\bthe\s+(?:ai\s+)?assistant\s+should\s+(?:comply|output|say|respond)\b"
        r"|\bfollowing\s+this\s+reasoning\s+chain\b",
        _I,
    ),
)



def _compile() -> tuple[CompiledPattern, ...]:
    compiled = []
    for name, category, confidence, source, flags in _PATTERNS:
        assert category in CATEGORIES, f"unknown category {category!r}"
        assert 0.0 <= confidence <= 1.0, f"bad confidence for {name}"
        compiled.append(
            CompiledPattern(
                name=name,
                category=category,
                confidence=confidence,
                regex=re.compile(source, flags),
            )
        )
    return tuple(compiled)


#: All compiled detectors, evaluated in order on every scan.
PATTERNS: tuple[CompiledPattern, ...] = _compile()


def iter_patterns() -> tuple[CompiledPattern, ...]:
    """Return the compiled pattern table (stable order)."""
    return PATTERNS
