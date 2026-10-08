# Engagement report

generated: 2026-10-08T23:23:12Z

_All numbers below are model predictions with rule provenance, not field results._

## Run `95116622-65e9-447e-9a40-d8ed58b8c893`

- scan: 127.0.0.1 (nmap)

## Run `b7bdfdeb-8425-4de1-97b6-3657d7bc543e`

- acquire: ./ret2func

## Run `8dde7a71-69cb-47c8-bf5c-c84ed306ae43`

- mode: handoff (prints a recipe; executes nothing)
- facts: target.facts
- applicable: ret2func, ret2libc
- selected: **ret2func**
  - ret2func <- app_ret2func (vuln=sof, pie=false, target_function=true)

## Run `8e97b822-a7c8-419c-b414-e0a89207eae4`

- mode: handoff (prints a recipe; executes nothing)
- facts: target.facts
- applicable: ret2func, ret2libc
- selected: **ret2func**
  - ret2func <- app_ret2func (vuln=sof, pie=false, target_function=true)

## Run `a76b14bd-a4e5-47f8-842b-73cbf3a80246`

- build: ret2func, offset 16 (win_symbol:win@4198870), 24 bytes -> payload.bin

## Run `22ca8494-b3e4-40a2-91cf-b8bf13a1fe05`

- harvest: {"win" => "0x4011d6"}

## Run `2f00fbff-77f1-4c9d-892b-0a691f4aace2`

- leak: {"win" => "0x4011d6"}
- outcome: **success** (ret2func)
