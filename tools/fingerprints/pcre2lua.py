"""Translate the subset of PCRE the fingerprint sources use into Lua patterns.

Lua patterns are not regular expressions. They have no alternation, no grouping
quantifier and no backreference, so a general translation does not exist. What
does exist is a translation of the shapes these five databases actually use,
plus an honest refusal for everything else - and a refusal is cheap, because a
rule that cannot be translated is simply not imported.

Two devices carry most of the work:

* **expansion.** `(?:a|b)c` has no Lua spelling, but `ac` and `bc` do. Anything
  the emitter cannot express directly is expanded into a set of alternatives
  that it can, bounded by MAX_VARIANTS so a pattern full of alternations cannot
  explode.
* **one capture.** These rules are read for exactly one value, the version, so
  the emitter puts parentheses around one group and drops the rest. That sizes
  the output below Lua's capture limit and removes the whole question of
  renumbering.

Correctness is not argued, it is measured: every source that ships examples has
each translated pattern run against them, and a pattern that does not reproduce
the documented extraction is dropped. See `verify.py`.
"""

import re

# A pattern that needs more than this many alternatives is not worth importing:
# the expansion costs more to match than the detection is worth, and in
# practice such a pattern is a catch-all rather than a fingerprint.
MAX_VARIANTS = 24

# Above this, a bounded repeat is read as an unbounded one. `[\w.-]{1,512}` is
# not a statement that 512 characters are meaningful; it is a guard against the
# catastrophic backtracking a PCRE engine can suffer and a Lua pattern cannot.
# Unrolling it literally produces a 3 KB pattern that matches the same strings
# more slowly, so beyond this bound the quantifier becomes * or +. It is a
# widening, and it is why every such rule has to clear its examples before it
# ships: 95 recog rules depend on this and each one is checked.
UNROLL_LIMIT = 16

# How many characters a range with an escaped endpoint may be spelled out into.
# Such a range cannot survive as a range in Lua, so it is written out member by
# member; a wide one would be a class longer than the rule it belongs to.
MAX_SPELT_RANGE = 64

# Lua's own metacharacters, escaped with % rather than backslash.
LUA_MAGIC = "^$*+?.([%-"


class Untranslatable(Exception):
    """The pattern uses PCRE this translator does not model."""


# --------------------------------------------------------------------- parsing

class Parser:
    """A recursive-descent parser for the PCRE subset, into a small AST.

    Nodes are tuples:
        ('lit', ch)                     one literal character
        ('class', body, negated)        a class, body already Lua-ready
        ('any',)                        .
        ('group', [alt, ...], index)    index is the PCRE group number or None
        ('rep', node, lo, hi, lazy)     hi is None for unbounded
        ('anchor', '^'|'$')
        ('bound', 'b'|'B')
    """

    def __init__(self, source):
        self.src = source
        self.pos = 0
        self.groups = 0

    # -- small helpers
    def eof(self):
        return self.pos >= len(self.src)

    def peek(self, ahead=0):
        at = self.pos + ahead
        return self.src[at] if at < len(self.src) else ""

    def take(self):
        ch = self.src[self.pos]
        self.pos += 1
        return ch

    def expect(self, ch):
        if self.eof() or self.src[self.pos] != ch:
            raise Untranslatable("expected %r at %d" % (ch, self.pos))
        self.pos += 1

    # -- grammar
    def parse(self):
        alts = self.parse_alternation()
        if not self.eof():
            raise Untranslatable("trailing input at %d" % self.pos)
        return ('group', alts, None)

    def parse_alternation(self):
        alts = [self.parse_sequence()]
        while self.peek() == "|":
            self.take()
            alts.append(self.parse_sequence())
        return alts

    def parse_sequence(self):
        items = []
        while not self.eof() and self.peek() not in "|)":
            items.append(self.parse_quantified())
        return items

    def parse_quantified(self):
        atom = self.parse_atom()
        while True:
            ch = self.peek()
            if ch == "*":
                self.take()
                lo, hi = 0, None
            elif ch == "+":
                self.take()
                lo, hi = 1, None
            elif ch == "?":
                self.take()
                lo, hi = 0, 1
            elif ch == "{":
                saved = self.pos
                spec = self.parse_braces()
                if spec is None:
                    self.pos = saved
                    return atom
                lo, hi = spec
            else:
                return atom

            lazy = False
            if self.peek() == "?":
                self.take()
                lazy = True
            elif self.peek() == "+":
                # A possessive quantifier matches the same language as the
                # greedy one; it only forbids backtracking, which changes
                # performance and not what is accepted.
                self.take()

            atom = ('rep', atom, lo, hi, lazy)

    def parse_braces(self):
        """{n}, {n,}, {n,m} - or None when the brace is a literal."""
        self.expect("{")
        digits = ""
        while self.peek().isdigit():
            digits += self.take()
        if not digits:
            return None
        lo = int(digits)
        hi = lo
        if self.peek() == ",":
            self.take()
            more = ""
            while self.peek().isdigit():
                more += self.take()
            hi = int(more) if more else None
        if self.peek() != "}":
            return None
        self.take()
        return lo, hi

    def parse_atom(self):
        ch = self.take()

        if ch == "(":
            return self.parse_group()
        if ch == "[":
            return self.parse_class()
        if ch == ".":
            return ('any',)
        if ch == "^":
            return ('anchor', '^')
        if ch == "$":
            return ('anchor', '$')
        if ch == "\\":
            return self.parse_escape()
        if ch in "*+?":
            raise Untranslatable("quantifier with nothing to quantify")
        return ('lit', ch)

    def parse_group(self):
        index = None
        if self.peek() == "?":
            self.take()
            kind = self.peek()
            if kind == ":":
                self.take()
            elif kind in "iomsxu-":
                # An inline flag group, (?i) or (?i:...). Only the
                # whole-pattern form is handled, by the caller lifting it out
                # before parsing; anything else changes semantics mid-pattern.
                raise Untranslatable("inline flags")
            elif kind == "P" and self.peek(1) == "<":
                self.take()
                self.take()
                while not self.eof() and self.peek() != ">":
                    self.take()
                self.expect(">")
                self.groups += 1
                index = self.groups
            elif kind == "<" and self.peek(1) not in "=!":
                self.take()
                while not self.eof() and self.peek() != ">":
                    self.take()
                self.expect(">")
                self.groups += 1
                index = self.groups
            else:
                # Lookaround, atomic group, conditional, recursion. A Lua
                # pattern cannot express any of them.
                raise Untranslatable("(?%s ..." % kind)
        else:
            self.groups += 1
            index = self.groups

        alts = self.parse_alternation()
        self.expect(")")
        return ('group', alts, index)

    def parse_class(self):
        """Parse [...] into a Lua class body.

        The dash carries the whole difficulty. Lua spells a range exactly as
        PCRE does, so a range separator must be passed through untouched, while
        a literal dash has to become %- or it silently turns two neighbouring
        characters into a range. Escaping every dash - the obvious version of
        this function - turned [0-9.] into [0%-9.], which matches three
        characters instead of eleven, and every version pattern in the corpus
        contains such a class.
        """
        negated = False
        if self.peek() == "^":
            self.take()
            negated = True

        # Items are (kind, text) where kind is 'ch' for something that can be a
        # range endpoint and 'set' for something that cannot.
        items = []
        first = True
        while True:
            if self.eof():
                raise Untranslatable("unterminated character class")
            ch = self.take()
            if ch == "]" and not first:
                break
            first = False

            if ch == "\\":
                items.append(self.class_escape())
                continue
            if ch == "[" and self.peek() == ":":
                items.append(('set', self.posix_class()))
                continue
            if ch == "-" and items and self.peek() not in ("]", ""):
                # A range, but only between two single characters. PCRE reads
                # [\d-z] as a literal dash too, and so does this.
                if items[-1][0] != 'ch':
                    items.append(('ch', "-"))
                    continue
                upper = self.take()
                if upper == "\\":
                    endpoint = self.class_escape()
                    if endpoint[0] != 'ch':
                        raise Untranslatable("range ending in a class escape")
                    upper = endpoint[1]
                elif upper == "[" and self.peek() == ":":
                    raise Untranslatable("range ending in a POSIX class")
                low = items.pop()[1]
                # Lua's matchbracketclass consumes a "%x" escape BEFORE it
                # tests for a range, so an escaped endpoint stops being an
                # endpoint: measured, "[\x25-\x2f]" became "[%%-/]", which Lua
                # reads as the three characters {%, -, /} rather than the
                # eleven the range names. Spell such a range out instead.
                if (escape_in_class(low) != low
                        or escape_in_class(upper) != upper):
                    if ord(upper) < ord(low):
                        raise Untranslatable("reversed range")
                    if ord(upper) - ord(low) > MAX_SPELT_RANGE:
                        raise Untranslatable("range too wide to spell out")
                    items.append(('set', "".join(
                        escape_in_class(chr(c))
                        for c in range(ord(low), ord(upper) + 1))))
                    continue
                items.append(('set',
                    escape_in_class(low) + "-" + escape_in_class(upper)))
                continue
            items.append(('ch', ch))

        if not items:
            raise Untranslatable("empty character class")

        body = ""
        for kind, text in items:
            body += escape_in_class(text) if kind == 'ch' else text
        return ('class', body, negated)

    def posix_class(self):  # noqa: D401 - returns the Lua text, not a tuple
        end = self.src.find(":]", self.pos)
        if end < 0:
            raise Untranslatable("unterminated POSIX class")
        name = self.src[self.pos + 1:end]
        self.pos = end + 2
        mapped = {
            "alpha": "%a", "digit": "%d", "alnum": "%w", "space": "%s",
            "upper": "%u", "lower": "%l", "punct": "%p", "xdigit": "%x",
            "cntrl": "%c", "print": "%g ", "graph": "%g",
        }.get(name)
        if mapped is None:
            raise Untranslatable("POSIX class [:%s:]" % name)
        return mapped

    def class_escape(self):
        """One escape inside [...], as ('ch', c) or ('set', lua_text).

        'ch' is returned only for something that may legally be a range
        endpoint; a class shorthand like \\d may not, and saying so here is
        what keeps [\\d-z] from being read as a range.
        """
        ch = self.take()
        # Inside a class the underscore can simply be added to the set. \W
        # cannot: Lua has no way to subtract a set from a bracketed class, and
        # emitting %W here would quietly admit the underscore.
        if ch == "w":
            return ('set', "%w_")
        if ch == "W":
            raise Untranslatable("\\W inside a character class")

        simple = CLASS_ESCAPES.get(ch)
        if simple is not None:
            if (simple.startswith("%") and len(simple) == 2
                    and simple[1].isalpha()):
                return ('set', simple)
            if len(simple) == 1:
                return ('ch', simple)
            return ('set', simple)
        if ch == "x":
            return ('ch', self.hex_escape())
        if ch.isdigit():
            raise Untranslatable("octal or backreference in class")
        return ('ch', ch)

    def hex_escape(self):
        if self.peek() == "{":
            self.take()
            digits = ""
            while self.peek() != "}":
                if self.eof():
                    raise Untranslatable("unterminated \\x{")
                digits += self.take()
            self.take()
        else:
            digits = self.take() + self.take()
        value = int(digits, 16)
        if value > 0xFF:
            raise Untranslatable("non-byte \\x escape")
        return chr(value)

    def parse_escape(self):
        if self.eof():
            raise Untranslatable("trailing backslash")
        ch = self.take()

        if ch in "bB":
            return ('bound', ch)
        if ch in "AZz":
            # \A and \z are the whole-subject anchors; against a single header
            # value they mean what ^ and $ mean. \Z differs only for a trailing
            # newline, which a header value does not carry.
            return ('anchor', '^' if ch == "A" else '$')
        if ch.isdigit():
            raise Untranslatable("backreference")
        if ch in "GKRXpPQEN":
            raise Untranslatable("\\%s" % ch)

        # PCRE's \w includes the underscore; Lua's %w does not. Mapping one
        # straight onto the other TRUNCATED a captured version at the first
        # underscore - measured, "Tomcat/([\w.]+)" against "Tomcat/9.0.1_beta"
        # gave PCRE "9.0.1_beta" and Lua "9.0.1". A truncated version is worse
        # than a miss: it mints a confident, wrong CPE and asks the API about a
        # release that never existed. \W is the same error negated, and matched
        # what PCRE rejects.
        if ch == "w":
            return ('class', "%w_", False)
        if ch == "W":
            return ('class', "%w_", True)

        klass = CLASS_ESCAPES.get(ch)
        if klass is not None:
            if (klass.startswith("%") and len(klass) == 2
                    and klass[1].isalpha()):
                return ('class', klass, False)
            if ch in MULTI_CHAR_ESCAPES:
                # A set, not a literal: emit it as a bracketed class so the
                # rest of the translator can quantify and negate it normally.
                return ('set', "".join(escape_in_class(c) for c in klass))
            return ('lit', klass)
        if ch == "x":
            return ('lit', self.hex_escape())
        return ('lit', ch)


# The escapes that mean a class or a control character. Lua's %a %d %s %w %u %l
# %p %x are the same idea with a different sigil; the negated forms are the
# uppercase Lua letters, which is exactly PCRE's convention too.
CLASS_ESCAPES = {
    "d": "%d", "D": "%D", "w": "%w", "W": "%W", "s": "%s", "S": "%S",
    "h": " \t", "v": "\r\n",
    # "\27" is OCTAL 27 in Python, which is 0x17 (ETB). PCRE's \e is ESC, 0x1B.
    "n": "\n", "r": "\r", "t": "\t", "f": "\f", "a": "\a", "e": "\x1b",
    "0": "\0",
}

# The entries above whose value is more than one character. They describe a SET
# ("\h" is space or tab), so outside a character class they cannot be emitted
# as a literal - and parse_escape used to wrap them as one, which made ord()
# raise TypeError on a string of length 2. build.translated and probes._lua
# catch only Untranslatable, so a single upstream rule containing \h or \v
# aborted the entire weekly rebuild.
MULTI_CHAR_ESCAPES = {ch for ch,
                      value in CLASS_ESCAPES.items() if len(value) > 1}


def escape_in_class(ch):
    """Escape one literal character for the inside of a Lua character class."""
    if ch in "%]^-":
        return "%" + ch
    if ch == "\0":
        return "%z"
    if ord(ch) < 0x20 or ord(ch) > 0x7E:
        raise Untranslatable("non-printable literal in class")
    return ch


def escape_literal(ch):
    """Escape one literal character for a Lua pattern."""
    if ch in LUA_MAGIC or ch == ")" or ch == "]":
        return "%" + ch
    if ch == "\0":
        return "%z"
    if ord(ch) < 0x20 or ord(ch) > 0x7E:
        raise Untranslatable("non-printable literal")
    return ch


# ------------------------------------------------------------------- expansion

def single_char(node):
    """The Lua spelling of a node that matches exactly one character, or None.

    Only such a node can carry a Lua quantifier: Lua applies * + - ? to a
    single character class, never to a group.
    """
    kind = node[0]
    if kind == 'lit':
        return escape_literal(node[1])
    if kind == 'any':
        # PCRE's . excludes newline unless DOTALL. Keeping that difference
        # matters here, because an unbounded . that crosses a line boundary is
        # how a pattern swallows the next header.
        return "[^\r\n]"
    if kind == 'class':
        body, negated = node[1], node[2]
        if (not negated and len(body) == 2 and body[0] == "%"
                and body[1].isalpha()):
            return body
        return "[" + ("^" if negated else "") + body + "]"
    if kind == 'group':
        # A group whose every branch is one character is a character class
        # wearing parentheses, and a class is the one thing Lua can quantify.
        # 37 recog rules are written as (?:a|b|c)+ and would otherwise be lost.
        return merge_alternation(node)
    return None


def merge_alternation(node):
    """`(?:a|b|\\d)` as a Lua class, when every branch is a single "
        "character."""
    alts, index = node[1], node[2]
    if index is not None:
        # Merging would dissolve the parentheses the capture needs.
        return None

    body = ""
    for sequence in alts:
        if len(sequence) != 1:
            return None
        item = sequence[0]
        if item[0] == 'lit':
            body += escape_in_class(item[1])
        elif item[0] == 'class':
            if item[2]:
                # A negated class cannot be unioned with anything by
                # concatenation: [^a] plus [^b] is not [^ab].
                return None
            body += item[1]
        else:
            return None
    return "[" + body + "]" if body else None


def repeat_single(piece, lo, hi, lazy):
    """A Lua spelling for `piece` repeated between lo and hi times."""
    if hi is not None and hi > UNROLL_LIMIT:
        # Only the UPPER bound is safe to relax. Dropping the lower one too
        # turned {20} into "one or more", which accepts what the original
        # rejects: measured, "^ID: ([\d.]+) [A-Z]{20}$" matched "ID: 1.2 X" and
        # minted a version from a subject PCRE refuses outright. The example
        # oracle cannot see this - it only asserts the recorded example still
        # matches, never that the widened pattern still rejects.
        hi = None
        lo = min(lo, UNROLL_LIMIT)
    if hi is None:
        if lo == 0:
            return piece + ("-" if lazy else "*")
        if lo == 1:
            return piece + piece + ("-" if lazy else "*")
        if lo <= 8:
            return piece * lo + piece + ("-" if lazy else "*")
        raise Untranslatable("{%d,} is too long to unroll" % lo)
    if hi == 0:
        return ""
    if hi - lo > UNROLL_LIMIT:
        raise Untranslatable("{%d,%d} is too long to unroll" % (lo, hi))
    # Lua's ? is the only bounded quantifier, and it too takes a single class,
    # so a bounded count is spelled out: the required copies, then the optional
    # ones. Optional copies are only sound trailing, which is what {n,m} means.
    return piece * lo + (piece + "?") * (hi - lo)


def expand(node, want):
    """Every Lua spelling of `node`, as a list of strings.

    `want` is the PCRE group number whose text is to be captured, or None. A
    variant that cannot reach that group is dropped by the caller, because a
    version rule that matches without extracting a version is not a version
    rule.
    """
    kind = node[0]

    if kind in ('lit', 'any', 'class'):
        return [single_char(node)]

    if kind == 'anchor':
        # ^ and $ are Lua anchors only at the very edges of the pattern, which
        # is checked once the whole string is assembled.
        return ["\x01" if node[1] == '^' else "\x02"]

    if kind == 'bound':
        if node[1] == 'B':
            raise Untranslatable("\\B")
        # Lua's frontier pattern is a real word boundary: %f[set] matches the
        # empty string where the previous character is outside the set and the
        # next is inside. Which of the two directions is meant depends on the
        # neighbours, so both are emitted and the assembler picks.
        return ["\x03"]

    if kind == 'rep':
        inner, lo, hi, lazy = node[1], node[2], node[3], node[4]
        piece = single_char(inner)
        if piece is not None:
            return [repeat_single(piece, lo, hi, lazy)]

        # A repeated group. Only the shapes that stay finite are expanded.
        if hi is None:
            raise Untranslatable("unbounded repeat of a group")
        if lo == 0 and hi == 1:
            inside = expand(inner, want)
            # The absent variant loses whatever the group would have captured.
            return [""] + inside
        if hi <= 3:
            out = [""] * 1
            variants = expand(inner, want)
            result = []
            for count in range(lo, hi + 1):
                if count == 0:
                    result.append("")
                    continue
                combos = [""]
                for _ in range(count):
                    combos = [a + b for a in combos for b in variants]
                    if len(combos) > MAX_VARIANTS:
                        raise Untranslatable("group repeat expands too far")
                result.extend(combos)
            del out
            return result
        raise Untranslatable("{%s,%s} of a group" % (lo, hi))

    if kind == 'group':
        alts, index = node[1], node[2]
        out = []
        for sequence in alts:
            combos = [""]
            for item in sequence:
                pieces = expand(item, want)
                combos = [a + b for a in combos for b in pieces]
                if len(combos) > MAX_VARIANTS:
                    raise Untranslatable("expansion exceeds %d "
                        "variants" % MAX_VARIANTS)
            out.extend(combos)
        if len(out) > MAX_VARIANTS:
            raise Untranslatable("expansion exceeds %d "
                "variants" % MAX_VARIANTS)
        if index is not None and index == want:
            # \x04 and \x05 stand in for the capture parentheses so that a
            # later pass can tell them from a literal ( the pattern happens to
            # match.
            out = ["\x04" + variant + "\x05" for variant in out]
        return out

    raise Untranslatable("unknown node %r" % (kind,))


# ------------------------------------------------------------------ assembling

def assemble(raw, anchored_by_default):
    """Turn one expanded variant into a final Lua pattern.

    Resolves the placeholders: anchors are only legal at the edges, a word
    boundary becomes the frontier pattern that suits its neighbours, and the
    capture markers become parentheses.
    """
    text = raw

    # Anchors. Lua reads ^ as an anchor only in first position and $ only in
    # last, and a pattern that anchors anywhere else means something PCRE does
    # and Lua does not.
    # A second "^" used to be deleted here before the check below could see it,
    # which turned an unmatchable PCRE into a matching Lua pattern: measured,
    # "^a^b(\d+)" became "^ab(%d%d*)" and matched "ab12", which PCRE cannot.
    # The refusal two lines down is the correct answer and was unreachable.
    if text.count("\x01") > 1 or text.count("\x02") > 1:
        raise Untranslatable("repeated anchor")
    if "\x01" in text and not text.startswith("\x01"):
        raise Untranslatable("^ away from the start")
    if "\x02" in text and not text.endswith("\x02"):
        raise Untranslatable("$ away from the end")

    starts = text.startswith("\x01")
    ends = text.endswith("\x02")
    text = text.replace("\x01", "").replace("\x02", "")

    # Word boundaries. Lua's %f[set] matches where the previous character is
    # outside the set and the next is inside it, so \b becomes %f[%w] when a
    # word follows it and %f[%W] when one ends there. Which of the two is
    # decided by the next ATOM, not the next byte: after "Tomcat" the pattern
    # continues "%-", whose first byte is the escape and whose atom is a
    # hyphen. Reading the byte made \bTomcat\b(?:-...)? emit %f[%w] before a
    # hyphen, a frontier that can never hold, and the rule matched nothing at
    # all.
    out = []
    for index, ch in enumerate(text):
        if ch != "\x03":
            out.append(ch)
            continue
        after = text[index + 1:].lstrip("\x04\x05")
        out.append("%f[%w]" if starts_with_word(after) else "%f[%W]")
    text = "".join(out)

    text = text.replace("\x04", "(").replace("\x05", ")")

    if starts or anchored_by_default:
        text = "^" + text
    if ends:
        text = text + "$"

    if text in ("", "^", "$", "^$"):
        raise Untranslatable("empty pattern")
    return text


# The Lua class shorthands that describe word characters, and those that
# do not.
#
# The negated forms belong on the OTHER side: %D is "not a digit" and %W is
# "not a word character", so neither can start a word. Listing them as word
# classes turned "\b\W" into "%f[%w]%W" - a start-of-word frontier immediately
# before a guaranteed non-word character, which can never match. Measured:
# "Tomcat\b\W+v(\d+)" became "Tomcat%f[%w]%W%W*v(%d%d*)" and matched nothing at
# all, where PCRE matched "Tomcat - v9".
#
# %g is dropped from the non-word set for the same reason in reverse: it is
# every printable except space, so it INCLUDES letters and digits and cannot
# be assumed non-word. It falls through to the "unresolvable" default instead.
WORD_CLASSES = set("dwalux")
NON_WORD_CLASSES = set("spcDW")


def starts_with_word(text):
    """Whether the next atom of a Lua pattern matches a word character.

    Used only to choose which frontier a \\b becomes, so an unresolvable case
    answers "word": that is the reading for a boundary at the start of a token,
    which is what nearly every \\b in the corpus is.
    """
    if not text or text.startswith("\x02"):
        # End of pattern. Lua reads the position past the last character as \0,
        # which is in %W, so a trailing boundary is the end-of-word frontier.
        return False

    head = text[0]
    if head == "%":
        nxt = text[1] if len(text) > 1 else ""
        if nxt in WORD_CLASSES:
            return True
        if nxt in NON_WORD_CLASSES:
            return False
        return nxt.isalnum() or nxt == "_"
    if head == "[":
        end = skip_class(text, 0)
        body = text[1:end - 1]
        if body.startswith("^"):
            # A class that negates the word characters themselves - "[^%w_]",
            # which is what \\W now becomes - can only match a NON-word
            # character, so a \\b in front of it is an end-of-word frontier.
            # Reading it as "word" put %f[%w] immediately before a guaranteed
            # non-word character: a frontier that can never hold. Any other
            # negated class usually excludes only punctuation, so what it
            # accepts is more likely a word character than not.
            excluded = body[1:]
            if "%w" in excluded or "%a" in excluded or "%d" in excluded:
                return False
            return True
        return any(ch.isalnum() or ch == "_" for ch in body) or "%w" in body \
            or "%d" in body or "%a" in body
    return head.isalnum() or head == "_"


# ---------------------------------------------------------------------- driver

INLINE_FLAGS = re.compile(r"^\(\?([imsxu]+)\)")


def anchors_somewhere(pattern):
    """Whether a PCRE contains ^ or $ outside a character class."""
    index, in_class = 0, False
    while index < len(pattern):
        ch = pattern[index]
        if ch == "\\":
            index += 2
            continue
        if ch == "[" and not in_class:
            in_class = True
        elif ch == "]" and in_class:
            in_class = False
        elif not in_class and ch in "^$":
            return True
        index += 1
    return False


def fold_case(pattern):
    """Rewrite a pattern so it matches either case, since Lua has no flag.

    Only literals and classes need it, and only where a letter appears. The
    result is longer but exact - which matters, because the alternative
    considered here was lowercasing the subject, and that would corrupt the
    version string the pattern is being run to extract.
    """
    out = []
    index = 0
    inside_class = False
    while index < len(pattern):
        ch = pattern[index]
        if ch == "%" and index + 1 < len(pattern):
            out.append(pattern[index:index + 2])
            index += 2
            continue
        if ch == "[" and not inside_class:
            inside_class = True
            out.append(ch)
            index += 1
            continue
        if ch == "]" and inside_class:
            inside_class = False
            out.append(ch)
            index += 1
            continue
        if ch.isalpha():
            if inside_class:
                # A range endpoint must not be split, or a-z becomes nonsense.
                if index + 1 < len(pattern) and pattern[index + 1] == "-":
                    out.append(ch)
                    index += 1
                    continue
                if out and out[-1] == "-":
                    out.append(ch)
                    index += 1
                    continue
                out.append(ch.lower() + ch.upper())
            else:
                out.append("[" + ch.lower() + ch.upper() + "]")
            index += 1
            continue
        out.append(ch)
        index += 1
    return "".join(out)


def translate(pattern, want_group=None, ignore_case=False, anchored=False,
              dot_newline=False):
    """Translate one PCRE into a list of equivalent Lua patterns.

    @param want_group the PCRE group number to capture, or None for a rule that
           only reports presence.
    @param anchored force a leading ^, for a field matched whole.
    @return list of Lua patterns; every one of them must be tried
    @raises Untranslatable when the pattern uses PCRE this cannot model
    """
    source = pattern
    match = INLINE_FLAGS.match(source)
    if match:
        flags = match.group(1)
        if "x" in flags:
            raise Untranslatable("extended mode")
        ignore_case = ignore_case or "i" in flags
        dot_newline = dot_newline or "s" in flags
        source = source[match.end():]
        if "m" in flags and anchors_somewhere(source):
            # Multiline changes what ^ and $ mean, and only that. A pattern
            # carrying neither is unaffected by the flag, so refusing it threw
            # away rules for no reason - Wordpress's version extractor among
            # them. A pattern that does anchor is refused, because Lua has no
            # per-line anchor to translate it into.
            raise Untranslatable("multiline mode with an anchor")

    parser = Parser(source)
    tree = parser.parse()

    if want_group is not None and want_group > parser.groups:
        raise Untranslatable("group %d does not exist" % want_group)

    variants = expand(tree, want_group)
    out = []
    seen = set()
    for variant in variants:
        if want_group is not None and variant.count("\x04") != 1:
            # Either this branch of the alternation cannot produce the version,
            # or it produces it twice. A repeated capture group emits both -
            # "(?:v(\d+)){1,2}" expands to "v(%d%d*)" AND "v(%d%d*)v(%d%d*)" -
            # and the second is refused by the reader's exact-one-capture rule
            # at scan time. It shipped anyway: bytes on every download, counted
            # by the publish gate as a live detection, and unable to fire.
            continue
        text = assemble(variant, anchored)
        # The anchor is taken here, before folding: case folding replaces every
        # letter with a two-element class, so a folded pattern has no literal
        # run left and the prefilter would have nothing to search for. A
        # lowercase anchor is a sound prefilter either way, because the runtime
        # searches a lowercased copy of the subject.
        anchor = literal_anchor(text)
        if ignore_case:
            text = fold_case(text)
        if dot_newline:
            text = text.replace("[^\r\n]", ".")
        if text not in seen:
            seen.add(text)
            out.append((text, anchor))

    if not out:
        raise Untranslatable("no variant reaches the capture")
    if len(out) > MAX_VARIANTS:
        raise Untranslatable("too many variants")
    return out


def units(lua_pattern):
    """Walk a Lua pattern as (literal_or_None, quantifier) units.

    A unit's literal is the one character it is guaranteed to match, or None
    for a class, a `.`, an anchor or a frontier. The quantifier is "", "*",
    "-", "+" or "?".
    """
    index = 0
    length = len(lua_pattern)
    while index < length:
        ch = lua_pattern[index]

        if ch == "%" and index + 1 < length:
            nxt = lua_pattern[index + 1]
            if nxt == "f":
                # %f[set] - a frontier, whose class is not a matched character.
                index += 2
                if index < length and lua_pattern[index] == "[":
                    index = skip_class(lua_pattern, index)
                continue
            literal = None if nxt.isalnum() else nxt
            index += 2
        elif ch == "[":
            end = skip_class(lua_pattern, index)
            literal = None
            index = end
        elif ch in "()^$":
            index += 1
            continue
        elif ch == ".":
            literal = None
            index += 1
        else:
            literal = ch
            index += 1

        quantifier = ""
        if index < length and lua_pattern[index] in "*-+?":
            quantifier = lua_pattern[index]
            index += 1
        yield literal, quantifier


def skip_class(pattern, index):
    """The index just past the character class starting at `index`."""
    cursor = index + 1
    if cursor < len(pattern) and pattern[cursor] == "^":
        cursor += 1
    if cursor < len(pattern) and pattern[cursor] == "]":
        cursor += 1
    while cursor < len(pattern):
        if pattern[cursor] == "%":
            cursor += 2
            continue
        if pattern[cursor] == "]":
            return cursor + 1
        cursor += 1
    return cursor


def literal_anchor(lua_pattern):
    """The longest guaranteed literal run in a Lua pattern, lowercased.

    The matcher uses it as a prefilter: a plain `find` for this substring is a
    memory scan where running the pattern is an interpreter loop, and a body
    that does not contain the literal cannot match the pattern. That is what
    makes a thousand rules affordable where a hundred and seventy-eight were
    not.

    Only `*`, `-` and `?` break a run. `+` does not: `ab+c` still guarantees
    the substring "abc", because at least one b sits between them. Treating `+`
    as a break lost the anchor on a third of the corpus; treating it as an
    ordinary character - which the first version of this function did - put a
    literal plus sign into the anchor and the prefilter then matched nothing at
    all.
    """
    best = ""
    current = ""
    for literal, quantifier in units(lua_pattern):
        if literal is None or quantifier in ("*", "-", "?"):
            current = ""
            continue
        current += literal
        if len(current) > len(best):
            best = current

    best = best.strip()
    return best.lower() if len(best) >= 3 else None


def literal_runs(lua_pattern):
    """Every guaranteed literal run in a Lua pattern, in order.

    `literal_anchor` returns only the longest, because the prefilter wants one
    substring. The timing gate wants them all: the input that costs a lazy
    pattern the most is one carrying every literal it looks for, so that the
    scan advances past each of them and only fails at the end. For
    `jquery[^"\'<>]-%.js%?ver=([%d.]+)` the runs are "jquery" and ".js?ver=",
    and their concatenation is precisely the 5.3-second input.
    """
    runs = []
    current = ""
    for literal, quantifier in units(lua_pattern):
        if literal is None or quantifier in ("*", "-", "?"):
            if len(current) >= 2:
                runs.append(current)
            current = ""
            continue
        current += literal
    if len(current) >= 2:
        runs.append(current)
    return runs


# Lua class shorthands whose members include digits.
DIGIT_BEARING = set("dwxSWgG")


def capture_can_hold_a_digit(lua_pattern):
    """Whether the captured group could ever contain a digit.

    The runtime refuses a capture with no digit in it, because a version
    without one is a word - a Debian codename, a product name, a stray token -
    and appending it to a CPE asks the service about a release that does not
    exist. A rule whose capture is a literal alternative therefore cannot fire
    at all, and shipping it is shipping a detection that is switched off.

    Two recog rules capture `sarge` and `squeeze` exactly this way.
    """
    start = lua_pattern.find("(")
    while start != -1 and start > 0 and lua_pattern[start - 1] == "%":
        start = lua_pattern.find("(", start + 1)
    if start == -1:
        return False

    depth, index = 0, start
    end = len(lua_pattern)
    while index < len(lua_pattern):
        ch = lua_pattern[index]
        if ch == "%":
            index += 2
            continue
        if ch == "[":
            index = skip_class(lua_pattern, index)
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                end = index
                break
        index += 1

    body = lua_pattern[start + 1:end]

    index = 0
    while index < len(body):
        ch = body[index]
        if ch == "%":
            nxt = body[index + 1] if index + 1 < len(body) else ""
            if nxt in DIGIT_BEARING or nxt.isdigit():
                return True
            index += 2
            continue
        if ch == "[":
            close = skip_class(body, index)
            inner = body[index:close]
            if inner.startswith("[^"):
                # A negated class admits digits unless it names them all.
                if not all(str(digit) in inner for digit in range(10)):
                    return True
            elif any(str(digit) in inner for digit in range(10)) \
                    or "%d" in inner or "%w" in inner or "%x" in inner:
                return True
            index = close
            continue
        if ch == "." or ch.isdigit():
            return True
        index += 1
    return False
