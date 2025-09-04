ROOT_DIR := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
PYTHON ?= python

.ONESHELL:
SHELL = bash
.SHELLFLAGS = -eux -O lastpipe -o pipefail -c

.DEFAULT_GOAL := install

$(ROOT_DIR)/venv:
	cd $(ROOT_DIR)
	$(PYTHON) -m venv venv/
	trap 'rm -vrf venv/' ERR
	[[ -r venv/Scripts/activate ]]  # Do use python.org's official version of python on Windows!

.PHONY: venv
venv: $(ROOT_DIR)/venv

.PHONY: requirements-dev
requirements-dev: venv
	cd $(ROOT_DIR)
	. venv/Scripts/activate
	python -m pip install -r requirements-dev.txt

.PHONY: install-pre-commit
install-pre-commit: venv
	cd $(ROOT_DIR)
	. venv/Scripts/activate
	#pre-commit install
	ln scripts/git-hooks/pre-commit .git/hooks/pre-commit

.PHONY: install
install: venv
	cd $(ROOT_DIR)
	. venv/Scripts/activate
	pip install .

.PHONY: install-editable
install-editable: venv
	cd $(ROOT_DIR)
	. venv/Scripts/activate
	pip install --editable .

.PHONY: check
check: venv
	cd $(ROOT_DIR)
	. venv/Scripts/activate
	python -m ruff check --fix --exit-non-zero-on-fix
	python -m ruff format --exit-non-zero-on-format

.PHONY: format
format: venv
	cd $(ROOT_DIR)
	. venv/Scripts/activate
	python -m ruff format
	python -m ruff check --fix
	python -m mypy --exclude-gitignore .

.PHONY: test
test: venv
	cd $(ROOT_DIR)
	. venv/Scripts/activate
	python -m pytest

.PHONY: freeze
freeze: venv
	cd $(ROOT_DIR)
	. venv/Scripts/activate
	pyinstaller \
	    --name calltoarms \
	    --onefile \
	    --noconsole \
	    --add-data src/calltoarms/assets:calltoarms/assets \
	    --hidden-import=flet_desktop \
	    --clean \
	    --uac-admin \
	    --noupx \
	    run.py
	! ( ldd dist/calltoarms | grep -vxiP '\s+\w+\.dll => /c/Windows/[\w/\-.]+\.dll \(0x[0-9a-z]{1,16}\)' )
	du -h dist/calltoarms

