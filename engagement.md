# Engagement report

generated: 2026-10-08T19:36:39Z

_All numbers below are model predictions with rule provenance, not field results._

## Run `9c30cf06-d3a0-4be1-9de2-6a74748bc82f`

- scan: 127.0.0.1 (nmap)

## Run `51135b5a-2240-488d-9fd3-fbda4d36ab27`

- acquire: ./ret2func

## Run `e1870960-e48a-4625-9098-112966e4ce37`

- mode: handoff (prints a recipe; executes nothing)
- facts: target.facts
- applicable: ret2func, ret2libc
- selected: **ret2func**
  - ret2func <- app_ret2func (vuln=sof, pie=false, target_function=true)

## Run `a3fd9fab-6f5f-4647-94ad-b4a62d16242e`

- mode: handoff (prints a recipe; executes nothing)
- facts: target.facts
- applicable: ret2func, ret2libc
- selected: **ret2func**
  - ret2func <- app_ret2func (vuln=sof, pie=false, target_function=true)

## Run `69bd566e-b7a6-443d-83cd-627a7eb53324`

- build: ret2func, offset 16 (win_symbol:win@4198870), 24 bytes -> payload.bin

## Run `dbddfddb-b851-40e8-bf4f-2667953a7de1`

- harvest: {"win" => "0x4011d6"}

## Run `7c23ca92-cdba-4684-8ed7-7870e13146b6`

- leak: {"win" => "0x4011d6"}
- outcome: **failure** (ret2func)
- outcome: **failure** (ret2func)
- outcome: **failure** (ret2func)
