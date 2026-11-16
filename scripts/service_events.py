"""Bounded, non-secret JSONL progress for the console frontend."""
import json
import sys

_stream = None


def enable(enabled):
    global _stream
    _stream = sys.stdout if enabled else None


def emit(event, **values):
    if _stream is not None:
        _stream.write(json.dumps({"event": event, **values}, ensure_ascii=False) + "\n")
        _stream.flush()


def result(value):
    if _stream is None:
        print(json.dumps(value))
    else:
        emit("result", result=value)


def error(message):
    if _stream is None:
        print(message, file=sys.stderr)
    else:
        emit("error", message=message)


class StageProgress:
    """Percent of explicit work stages, with byte progress inside a write stage."""

    def __init__(self, stages, label=lambda value: value, enabled=True):
        self.stages = tuple(stages)
        if not self.stages or len(set(self.stages)) != len(self.stages):
            raise ValueError("Progress stages must be nonempty and unique")
        self.label = label
        self.index = -1
        self.fraction = 0.0
        self.done = False
        self.enabled = enabled

    def start(self, stage, label=None):
        index = self.stages.index(stage)
        if index < self.index or self.done:
            raise ValueError("Progress cannot move backwards")
        if index != self.index:
            self.index, self.fraction = index, 0.0
        self.status = label if label is not None else self.label(stage)
        self._emit("phase")

    def update(self, current, total):
        if self.index < 0 or self.done or total <= 0:
            raise ValueError("An active stage and a positive byte count are required")
        self.fraction = max(self.fraction, min(1.0, max(0.0, current / total)))
        self._emit("progress", current=current, total=total)

    def complete(self, label):
        self.done = True
        self.status = label
        self._emit("phase")

    def _emit(self, event, **values):
        if not self.enabled:
            return
        total = len(self.stages)
        done = total if self.done else self.index + int(self.fraction == 1.0)
        percent = 100 if self.done else min(99, int(100 * (self.index + self.fraction) / total))
        emit(event, phase=self.status, overall_percent=percent,
             steps_done=done, steps_total=total, **values)
