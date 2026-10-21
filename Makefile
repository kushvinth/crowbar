SHELL := /bin/bash
PY ?= python3
HV := ./bin/crowbar

.PHONY: all sync build update test test-unit test-corpus check selftest precommit \
        doctor stats map verify link unlink clean demo

all: sync build

sync:
	$(PY) -m crowbar.cli sync

build:
	$(PY) -m crowbar.cli build

update:
	$(PY) -m crowbar.cli update --deep

test: test-unit test-corpus

test-unit:
	$(PY) -m tests.test_unit

test-corpus:
	$(PY) -m tests.test_corpus

check:
	$(PY) scripts/check.py

selftest:
	$(PY) scripts/selftest.py

precommit:
	pre-commit run --all-files

doctor:
	$(HV) doctor

stats:
	$(HV) stats

map:
	$(HV) map --tables

verify:
	$(HV) verify

link:
	$(HV) link $(PWD)

unlink:
	$(HV) unlink $(PWD)

clean:
	rm -rf data index/crowbar.db index/crowbar.db.tmp index/manifest.json index/state.json
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

# README GIFs from the asciinema casts (needs agg: nix run nixpkgs#asciinema-agg)
AGG ?= agg --theme monokai --font-size 16 --idle-time-limit 2 --last-frame-duration 4
demo:
	$(AGG) website/demo.cast docs/assets/demo.gif
	$(AGG) assets/agent-session.cast docs/assets/agent-session.gif
