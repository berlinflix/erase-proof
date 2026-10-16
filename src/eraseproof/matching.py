"""Binary-safe Aho-Corasick matching; Latin-1 preserves byte offsets exactly."""
import ahocorasick

from .models import EraseProofError


class Matcher:
    def __init__(self, patterns):
        self.patterns = tuple(patterns)
        self.automaton = ahocorasick.Automaton()
        grouped = {}
        for index, pattern in enumerate(self.patterns):
            if not pattern:
                raise EraseProofError("Empty search patterns are refused.")
            grouped.setdefault(pattern, []).append(index)
        for pattern, indices in grouped.items():
            self.automaton.add_word(pattern.decode("latin-1"), (len(pattern), tuple(indices)))
        if grouped:
            self.automaton.make_automaton()

    def iter(self, data):
        if self.patterns:
            for end, (length, indices) in self.automaton.iter(data.decode("latin-1")):
                for index in indices:
                    yield end-length+1, index

    def first(self, data):
        # C-level find avoids enumerating millions of repeated one-byte hits
        # for small reference sets. Larger sets use the shared automaton.
        if len(self.patterns) <= 32:
            return [(at, index) for index, pattern in enumerate(self.patterns) if (at := data.find(pattern)) >= 0]
        found = {}
        for count, (at, index) in enumerate(self.iter(data)):
            found.setdefault(index, at)
            if len(found) == len(self.patterns):
                break
            if count >= 1_000_000:
                raise EraseProofError("Search hit limit exceeded; a complete clean verdict cannot be established.")
        return [(at, index) for index, at in found.items()]
