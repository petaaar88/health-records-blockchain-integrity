# Health Records Blockchain Integrity

This project implements a distributed health record system using blockchain to ensure data integrity, security, and controlled access with patient approval. Built with Python, it offers a simple interface for managing medical records and demonstrates how blockchain can securely integrate healthcare data.



## Table of Contents
- [Features](#features)
- [Medical Record Creation & Verification Process](#medical-record-creation--verification-process)
- [Project Structure](#project-structure)
- [Blockchain Architecture](#blockchain-architecture)
  - [Consensus and mining](#consensus-and-mining)
  - [Persistence](#persistence)
  - [Networking](#networking)
- [On-Chain Data Model](#on-chain-data-model)
- [Server-Blockchain Integration](#server-blockchain-integration)
- [API Overview](#api-overview)
- [Setup Instructions](#setup-instructions)
  - [Prerequisites](#prerequisites)
  - [Backend Setup](#backend-setup)
  - [Run Blockchain Network](#run-blockchain-network)
  - [Run API](#run-api)
  - [Run Client](#run-client)
- [Limitations](#limitations)

## Features
- Create health records (doctor) with dynamic fields; server encrypts and stores; integrity hash written to blockchain
- Patient manages access requests from doctors; shares per‑record secret keys
- Patient views and verifies records via blockchain
- Doctor searches patients, requests access, reads records when approved
- Proof of work conscensus mechanism

## Medical Record Creation & Verification Process

1) **Record Creation**: When a doctor creates a new medical record, the server first encrypts the record’s data and nodes in blockchain are computing a unique canonical hash from the encrypted payload.
2) **Storage**: The encrypted record is then saved to MongoDB, and the hash is stored on the blockchain to provide immutable proof of authenticity.
3) **Patient Verification**: Later, when a patient wants to confirm the integrity of their record, they submit a verification request using the record’s unique `secret_key`.
4) **Integrity Check**: The server decrypts the stored record, recalculates its hash, and compares it with the on-chain `health_record_hash`.
5) **Verification Result**: The system returns a verification response indicating whether the record remains authentic or has been altered since its creation.

## Project Structure

- `client/` – React front‑end (MUI, Tailwind)
- `backend/server/` – Flask API 
- `backend/blockchain/` – WebSocket peer, PoW chain, JSON persistence
- `db/` – MongoDB dump 


## Blockchain Architecture

Core components (see [`backend/blockchain/backend/...`](https://github.com/petaaar88/health-records-blockchain-integrity/tree/main/backend/blockchain/backend)):
- Chain: manages difficulty, mining control, validation, and persistence (`chain.py`)
- BlockHeader: `height`, `difficulty`, `miner`, `previous_block_hash`, `timestamp`, `block_hash` (`block_header.py`)
- Block: contains a `Transaction` and header; performs PoW mining and hash computation (`block.py`)
- TransactionBody: `creator`, `patient`, `health_record_id`, `date`, `health_record_hash` (`transaction_body.py`)
- Peer: Node in blockchain network (`network/peer.py`)

### Consensus and mining:
- Proof‑of‑Work with `difficulty` variable
- Genesis block created at startup with fixed previous hash and id
- `create_new_block()` mines a block from the current pending transaction
- Chain validity: re‑computes block hashes and verifies link to previous hash

### Persistence:
- Each node writes JSON files under `backend/blockchain/db/`
- Chain is stored on `<PORT>_chain.json`  
- Accounts (public and private keys of accounts) are stored on `<PORT>_accounts.json`

### Networking:
- Each node runs a WebSocket peer
- Nodes can bootstrap from a known peer and then connect to additional peers
- Example: `python backend/blockchain/run.py 5001` (first node); `python backend/blockchain/run.py 5002 5001` (second node joins 5001)


## On‑Chain Data Model

TransactionBody fields:
- `creator`: public key of the authority/doctor creating the record entry
- `patient`: patient’s public key
- `health_record_id`: identifier linking blockchain entry to off‑chain encrypted record
- `date`: ISO timestamp for creation
- `health_record_hash`: canonical SHA‑256 hash of the off‑chain record payload


## Server–Blockchain Integration

- The Flask server communicates with a blockchain node over WebSocket
- Env `PEER_FOR_COMMUNICATION` points to a node URI (e.g., `ws://localhost:5001`)
- Utility `send_to_blockchain_and_wait_response` (see `backend/server/util/util.py`) sends a message and awaits response
- On record creation, server computes the record’s canonical hash and submits a transaction; on verification, server fetches the on‑chain hash and compares


## API Overview

Auth
- `POST /api/login` – returns JWT with `user_type` claim
- `POST /api/auth/verify` – validate/inspect token

Entities (provisioning/lookup)
- `POST /api/patients`
- `POST /api/health-authority`
- `POST /api/doctors`
- `GET /api/doctors/:id`
- `GET /api/health_authority/:id`
- `GET /api/patients/:id`
- `GET /api/patients/personal_id/:pid`
- `GET /api/central-authority/:id`

Health Records
- `POST /api/health-records` – create (doctor)
- `GET /api/health-records` – list (patient)
- `GET /api/health-records/secret_key/:hr_id` – get key if authorized
- `GET /api/health-records/patient/:personal_id` – doctor view by patient PID
- `POST /api/health-records/verify/:hr_id` – verify integrity with `secret_key`
- `POST /api/health-records/decrypt/:hr_id` – server‑side decrypt helper

Access Requests
- `POST /api/requests` – doctor → patient
- `GET /api/requests/patient` – patient inbox
- `GET /api/requests/doctors` – doctor outbox
- `PATCH /api/requests/:id` – patient accepts; attaches `secret_key`
- `DELETE /api/requests/:id`

## Setup Instructions

### Prerequisites

To run the entire system successfully, make sure the following dependencies are installed on your computer:

- **Node.js** ( 20+ ) – required to run the client, manage packages via npm, and serve the frontend application.

- **Python** ( 3.13 ) – required to run the server and blockchain nodes, since those components are written in Python.
- **Mongo DB** - document-based database for storing data.
- **MongoDB Command Line Database Tools** (Optional) - required for restoring database from a [dump](https://github.com/petaaar88/health-records-blockchain-integrity/tree/main/db).

### Backend Setup

1. First change folder to backend

```
cd backend
```
2. Create virtual enviroment for python

```
python -m venv venv
```
3. Activate virtual enviroment
```
.\venv\Scripts\activate
```
4. Install dependencies

```
pip install -r requirements.txt
```

### Run Blockchain Network

To ensure network consensus and proper blockchain synchronization, the system requires at least three active nodes, and the total number of nodes must be odd (e.g., 3, 5, 7) to prevent tie votes during validation.

In this project there is already blockchain network that consist of nodes on ports `5001`, `5002`, `5003`. You can remove this network by deleting everything inside the [`backend/blockchain/db`](https://github.com/petaaar88/health-records-blockchain-integrity/tree/main/backend/blockchain/db) directory. (**Note**: Deleting this network will invalidate the medical records stored in [MongoDB](https://github.com/petaaar88/health-records-blockchain-integrity/tree/main/db) for this project!). 
 
1. Start first node (port 5001):
```
python blockchain/run.py 5001
```

2. Start second node (port 5002) and connect to 5001:
```
python blockchain/run.py 5002 5001
```

3. Start third node (port 5003) and connect to 5002 and 5001:
```
python blockchain/run.py 5003 5002 5001
```

### Run API 

Before starting the Flask API, you need to set up MongoDB. In the [`db`](https://github.com/petaaar88/health-records-blockchain-integrity/tree/main/db) folder, there is a MongoDB dump that will be used to create the database.

1. Go to dump folder
```
cd db
```

2. Restore database
```
mongorestore --db health-system --drop dump/health-system
```
3. Create .env file and copy content from `.env.example`

```
JWT_SECRET=<secret_key>
DB_NAME=<database_name>
DB=<connection_url>
PEER_FOR_COMMUNICATION=<websocket_url>
```
4. Run API
```
python server/server.py
```
Server will run on port `5000` by default.

### Run Client

1. Change folder to backend
```
cd client
```
2. Install dependencies
```
npm install
```
3. Create .env file and copy content from `.env.example`

```
VITE_API_URL=<api_url>
```
4. Run client
```
npm run dev
```
Client will run on port `5173` on default.



## Limitations 

- Educational PoW chain without production‑grade consensus or networking hardening
- JSON persistence for simplicity; consider proper databases 
- Improve key management and end‑to‑end encryption strategy
