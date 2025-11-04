# Project Documentation: Health Records Blockchain Integrity

This document describes the system’s goals, requirements, architecture, and key implementation details.


## 1. Introduction

Problem. Electronic health records must be tamper‑evident without exposing sensitive data. Stakeholders (patients, doctors, authorities) require verifiable provenance and controlled access.

Goal. Combine symmetric encryption for confidentiality with a private blockchain for integrity proofs so stakeholders can verify that records weren’t altered.


## 2. Functional Requirements

- Authentication and roles: patients, doctors, health authorities, central authority
- Create health records (doctor) with dynamic medical fields and metadata
- Encrypt records at rest and store integrity hashes on blockchain
- Patients view their records and verify integrity
- Doctors request access; patients approve and share per‑record secret keys
- Entity lookups for doctors, authorities, and patients


## 3. Non‑Functional Requirements

- Security: AES‑CBC encryption; JWT with expiration; CORS; server‑side validation
- Integrity: deterministic hashing and on‑chain storage; verification route
- Availability: independent blockchain peer; Mongo persistence
- Extensibility: modular services; simple chain/transaction model for growth


## 4. Architecture Overview

- Client (React): authentication, dashboards per role, forms for record creation and verification UI
- Server (Flask): JWT auth, business logic, AES encryption/decryption, Mongo CRUD, blockchain broker via WebSocket
- Blockchain Node: custom PoW chain; maintains Block{Header, Transaction}; persists JSON; WebSocket networking
- Database (MongoDB): collections include `patients`, `doctors`, `health_authorities`, `central_authority`, `health_records`, `requests_for_health_records`

Flow highlights
1) Create record: doctor submits → server encrypts payload → stores doc → computes canonical hash → sends transaction to blockchain
2) Access: doctor requests → patient approves by attaching secret key to request
3) Verify: patient posts `secret_key` → server decrypts and recomputes hash → compares to on‑chain transaction


## 5. Data Model (MongoDB)

- patients: `_id`, `first_name`, `last_name`, `personal_id`, `date_of_birth`, `gender`, `address`, `phone`, `citizenship`, `password` (hash), `public_key`, `private_key`, `health_records[]`
- doctors: `_id`, `first_name`, `last_name`, `health_authority_id`, `password` (hash)
- health_authorities: `_id`, `name`, `type`, `address`, `phone`, `password` (hash), `public_key`, `private_key`, `doctors[]`, `patients[]`
- central_authority: `_id`, `name`, `password` (hash), ...
- health_records: encrypted fields + metadata (`_id`, `patient_id`, `doctor_id`, `health_authority_id`, names, `date`, dynamic medical fields encrypted at rest)
- requests_for_health_records: `_id`, `doctor_id`, `patient_id`, `health_record_id?`, `key` (base64 secret key when approved), timestamps/state


## 6. Security Design

- Encryption: AES‑128 using a 16‑byte random key; `encrypt(data, key)` returns `IV || ciphertext` (IV prepended)
- Keys: `generate_secret_key_b64()` produces base64 strings; `convert_secret_key_to_bytes()` restores raw bytes
- Identity & JWT: `POST /api/login` returns JWT with `user_type`; decorators enforce role access; `POST /api/auth/verify` checks validity/expiry
- Data exposure: server strips sensitive fields (e.g., `password`, `private_key`) before responses
- Hashing: SHA‑256 / double‑SHA used in blockchain; server canonicalizes payloads when hashing for integrity


## 7. Blockchain Design

Objects
- TransactionBody: `creator`, `patient`, `health_record_id`, `date`, `health_record_hash`
- BlockHeader: `height`, `difficulty`, `miner`, `previous_block_hash`, `timestamp`, `block_hash`
- Block: PoW mining and linkage validation

Chain Behavior
- Genesis block at height 0 persisted to `backend/blockchain/db/<port>_chain.json`
- Validation checks each block’s computed hash and previous link
- Lookup APIs: `find_health_record(health_record_id)`, `find_all_transactions_with_public_key(public_key)`

Networking
- WebSocket peer (`backend/blockchain/run.py`) maintains connections and synchronizes with known peers
- Server talks to blockchain via `websockets` using `PEER_FOR_COMMUNICATION`

Persistence
- JSON per node for chain and accounts: `backend/blockchain/db/<port>_chain.json`, `backend/blockchain/db/<port>_accounts.json`


## 8. API Specification (High‑Level)

Auth
- `POST /api/login`: `{ id, password }` → `{ access_token }`
- `POST /api/auth/verify`: header `Authorization: Bearer <token>` or body `{ token }` → validity/claims

Health Records
- `POST /api/health-records` (doctor): dynamic JSON; creates encrypted record, writes hash on chain
- `GET /api/health-records` (patient): `{ health_records: [{ health_record, key? }] }`
- `GET /api/health-records/secret_key/:hr_id`: return per‑record secret key when authorized
- `POST /api/health-records/decrypt/:hr_id`: `{ secret_key }` → decrypted content
- `POST /api/health-records/verify/:hr_id`: `{ secret_key }` → `{ blockchain_response }`

Requests
- `POST /api/requests` (doctor): create access request to a patient
- `GET /api/requests/patient` (patient inbox)
- `GET /api/requests/doctors` (doctor outbox)
- `PATCH /api/requests/:id` (patient): `{ secret_key }` approve/share
- `DELETE /api/requests/:id`

Entities
- `GET /api/patients/:id`, `GET /api/patients/personal_id/:pid`
- `GET /api/doctors/:id`, `GET /api/health_authority/:id`, `GET /api/central-authority/:id`


## 9. Front‑End Overview

- Routing: `/login`, `/dashboard` (protected)
- Role dashboards
  - Patient: list and verify records; manage requests
  - Doctor: search patients, request access, view authorized records; add records
  - Health Authority: overview of doctors/patients within the authority
  - Central Authority: global summaries
- Components: `HealthRecordForm`, `HealthRecord`, `PatientHealthRecords`, `SearchPatients`, `PatientRequests`, role dashboards, `ProtectedRoute`




