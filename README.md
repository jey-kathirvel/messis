# 🌴 Messis AI

## Smart Agriculture Management System

**Product Name:** Messis AI
**Tagline:** *Harvest • Crop • Reaping Season*
**Subtitle:** Smart Agriculture Management System

---

# Version

**Current Application Version**

```text
0.5.1
```

**Current Release Name**

```text
v0.5.1-uat-hardened
```

**Current Status**

```text
Production Active — Phase 2 UAT Hardening
```
---

# Project Overview

Messis AI is an enterprise-grade Agriculture ERP platform designed primarily for coconut farm management.

The system helps farm owners digitize the complete farming lifecycle including:

* Farm Management
* Coconut Tree Management
* Tree Activities
* Harvest Scheduling
* Expense Tracking
* Revenue Management
* Profitability
* Reports
* Multi-user Security
* Business Analytics

The application is designed to be simple for farmers while maintaining enterprise-grade architecture internally.

---

# Technology Stack

## Backend

* Python 3.12
* FastAPI
* SQLAlchemy 2.x
* PostgreSQL
* Jinja2
* Starlette Sessions

---

## Frontend

* Tailwind CSS
* Alpine.js
* Chart.js
* Vanilla JavaScript

---

## Server

* Ubuntu 24.04 LTS
* Apache Reverse Proxy
* Uvicorn
* systemd

---

## Database

PostgreSQL

Current database

```
messis_db
```

---

# Production Environment

Application Root

```
/opt/messis
```

Virtual Environment

```
/opt/messis/.venv
```

Application Service

```
messis.service
```

Backend

```
127.0.0.1:8080
```

Production URL

```
https://messis.ads-ai.in
```

---

# High Level Architecture

```
Browser

        │

        ▼

Apache Reverse Proxy

        │

        ▼

Uvicorn

        │

        ▼

FastAPI

        │

        ▼

SQLAlchemy

        │

        ▼

PostgreSQL
```

---

# Core Modules

## Authentication

* User ID
* 6 Digit Passcode
* Argon2 Password Hashing
* Session Authentication
* Account Lock Protection
* Secure Cookies

---

## Farm Management

Manage

* Farms
* Area
* Village
* Tree Count
* Farm Status
* Notes

---

## Coconut Tree Management

Track

* Total Trees
* Productive Trees
* Young Trees
* Diseased Trees
* Dead Trees

---

## Tree Activities

Supports

* Watering
* Fertilizer
* Pesticide
* Irrigation
* Pruning
* Pest Control
* Disease Inspection
* General Maintenance

---

## Harvest

Supports

* Harvest Schedule
* Harvest Recording
* Harvest History
* Yield Analysis

---

## Expenses

Supports

* Labour
* Diesel
* Fertilizer
* Pesticide
* Transport
* Repairs
* Miscellaneous

---

## Sales

Supports

* Coconut Sales
* Tender Coconut Sales
* Buyer Management
* Revenue Tracking

---

## Dashboard

Displays

* Farms
* Trees
* Activities
* Revenue
* Expenses
* Profit
* Harvest Alerts

---

## Reports

Generate

* Daily Report

* Monthly Report

* Farm Report

* Expense Report

* Revenue Report

* Harvest Report

---

# Current Database Tables

Current production tables

```
users
farms
audit_logs
coconut_trees
tree_activities
```

---

# Authentication Flow

```
User

↓

Login Screen

↓

User ID

↓

6 Digit Passcode

↓

Argon2 Verification

↓

Session Creation

↓

Dashboard
```

---

# Multi User Architecture

Each user can only access

* Own Farms
* Own Expenses
* Own Revenue
* Own Activities
* Own Reports

No user can access another user's data.

---

# Security Features

* Argon2 Password Hashing
* Session Middleware
* Secure Cookies
* Login Attempt Limiting
* Account Locking
* Audit Logging
* Owner Data Isolation

---

# Directory Structure

```
/opt/messis

│

├── app/

│   ├── main.py

│   ├── database.py

│   ├── models.py

│   ├── security.py

│   ├── config.py

│   ├── templates/

│   ├── static/

│

├── scripts/

├── docs/

├── tests/

├── backups/

├── .venv/

├── README.md

└── .gitignore
```

---

# Development Principles

Every change must

* Preserve existing functionality
* Preserve production data
* Preserve authentication
* Maintain owner isolation
* Include validation
* Include rollback
* Include testing

---

# Coding Standards

* Production quality only
* No hardcoded credentials
* No destructive SQL
* Mobile responsive UI
* Strong typing
* Clean architecture
* Modular implementation
* Reusable components

---

# Patch Methodology

Every enhancement follows numbered patches.

Example

```
PATCH-001

PATCH-002

PATCH-003

PATCH-UAT-001

PATCH-HARVEST-001
```

Each patch must

* Create backups
* Validate syntax
* Validate imports
* Validate database
* Restart service
* Validate service
* Validate application
* Stop for approval

---

# Deployment Checklist

Deployment includes

* Apache Reverse Proxy
* HTTPS
* SSL
* systemd
* Production Validation
* Smoke Testing
* Health Checks

---

# Backup Strategy

Planned

* Daily Database Backup
* Daily Application Backup
* 14 Day Retention
* Restore Scripts
* Backup Validation

---

# Monitoring

Planned

* Service Health
* Disk Usage
* Database Connectivity
* SSL Expiry
* Backup Verification

---

# Git Workflow

Recommended Branches

```
main

develop

feature/*
```

Every patch

```
Create Branch

↓

Develop

↓

Validate

↓

Merge

↓

Tag Release
```

---

# Release Naming

Example

```
v0.5.1-uat-hardened

v0.6.0-harvest

v0.7.0-expense

v0.8.0-sales

v1.0.0-production
```

---

# Current Project Roadmap

Completed

✅ Authentication

✅ Farm Management Foundation

✅ Tree Activities Foundation

✅ Production Deployment

✅ SSL

✅ Apache

✅ systemd

Pending

⬜ UAT

⬜ Harvest Cycle

⬜ Harvest Recording

⬜ Expenses

⬜ Revenue

⬜ Analytics

⬜ Reports

⬜ Backup Automation

⬜ Monitoring

⬜ Production Certification

---

# Recovery

Restart Application

```
sudo systemctl restart messis.service
```

Application Status

```
sudo systemctl status messis.service
```

View Logs

```
journalctl -u messis.service -f
```

Apache Status

```
sudo systemctl status apache2
```

---

# Project Philosophy

Messis AI is built with one primary goal:

> **Empower every farmer with enterprise-grade technology through a simple, reliable, and production-ready agriculture management platform.**

The system is designed to scale from a single coconut farm to large multi-farm agricultural enterprises while maintaining security, performance, maintainability, and an excellent user experience.
