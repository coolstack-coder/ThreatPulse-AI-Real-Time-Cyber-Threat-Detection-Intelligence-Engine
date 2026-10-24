.PHONY: install ui dev run demo test lint eval bench pcap docker

install:            ## Python venv + dashboard deps
	python3 -m venv .venv && .venv/bin/pip install -e ".[dev,capture]"
	cd frontend && npm install

ui:                 ## Build the dashboard (served by the engine at /)
	cd frontend && npm run build

run: ui             ## Engine + dashboard on http://127.0.0.1:8000
	.venv/bin/threatpulse run

demo: ui            ## Same, with a rotating attack every 60s
	.venv/bin/threatpulse run --auto-attack 60 --intensity 1.5

dev:                ## Hot-reload dashboard on :5173 (run `make run` in another terminal)
	cd frontend && npm run dev

test:
	.venv/bin/pytest -q

lint:
	.venv/bin/ruff check threatpulse tests

eval:               ## Recall / time-to-detect / false-positive report
	.venv/bin/threatpulse evaluate --seeds 3 --out docs/EVALUATION.md

bench:
	.venv/bin/threatpulse benchmark

pcap:               ## Export a labelled kill-chain PCAP for Wireshark
	.venv/bin/threatpulse export-pcap --out threatpulse-demo.pcap

docker:
	docker compose up --build
