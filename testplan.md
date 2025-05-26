# StudentVC X.509 Integration Test Plan

## 1. Introduction

This document outlines the test plan for the X.509 certificate integration within the StudentVC project. It focuses specifically on verifying the security aspects and performance optimizations introduced in Phase 4, while also ensuring the robustness of the features developed in Phases 1-3. Additionally, it covers testing for HAVID specification compliance and OID4VC/OID4VP integration features.

## 2. Objectives

*   Verify the secure implementation of X.509 certificate handling, validation, and binding.
*   Validate the effectiveness of the credential status mechanism (StatusList2021).
*   Verify HAVID specification compliance, including bidirectional linkage and challenge-response protocols.
*   Validate OID4VC/OID4VP integration features, including dual-proof presentations and selective disclosure.
*   Assess the performance impact of the X.509 integration and identify bottlenecks.
*   Ensure the overall stability, reliability, and interoperability of the enhanced StudentVC system.
*   Confirm that all security vulnerabilities identified during the audit are addressed.
*   Validate that performance optimizations meet defined targets.

## 3. Scope

### 3.1. In Scope

*   **Security Testing:**
    *   Cryptographic implementation review (key generation, signing, verification).
    *   Certificate validation logic (trust chain, revocation, expiration, constraints).
    *   Identity binding security (DID-X.509 linkage).
    *   Challenge-response protocol security and signature verification.
    *   Certificate lifecycle monitoring and rekeying detection.
    *   Input validation for API endpoints related to X.509 and status lists.
    *   Access control for certificate management and status updates.
    *   Protection against common web vulnerabilities (OWASP Top 10) related to new features.
    *   Testing resilience against known attacks on X.509 and DID systems.
*   **HAVID Compliance Testing:**
    *   Bidirectional linkage validation between X.509 certificates and DIDs.
    *   Challenge-response protocol for proving cryptographic control.
    *   Certificate lifecycle monitoring and rekeying detection.
    *   DID updates in response to X.509 certificate changes.
    *   CA-assisted DID creation from CSR key material.
*   **OID4VC/OID4VP Integration Testing:**
    *   Enhanced issuer metadata with X.509 certificate information.
    *   Dual-proof credential offers and presentations.
    *   X.509 metadata embedding in verifiable credentials.
    *   Verification of credentials using both DID and X.509 trust paths.
    *   Selective disclosure of certificate attributes.
*   **Performance Testing:**
    *   Certificate validation time under various loads.
    *   Credential issuance and verification latency with X.509 data.
    *   Status list generation and checking performance.
    *   Challenge-response protocol performance.
    *   Resource utilization (CPU, memory) during peak operations.
    *   Scalability testing for concurrent users/requests.
*   **Functional Testing (Regression):**
    *   End-to-end credential lifecycle (issue, present, verify, revoke/suspend, verify status) with X.509 integration.
    *   Verification of `did:web` and `did:key` resolution with certificate data.
    *   Correct handling of different credential status states (active, revoked, suspended).
    *   Functionality of X.509-related API endpoints (`/x509/challenge`, `/x509/verify-control`, `/x509/verify-binding`).
*   **Usability Testing:**
    *   Clarity and correctness of documentation related to X.509 setup and usage.
    *   Ease of configuring trusted CAs and issuer certificates.

### 3.2. Out of Scope

*   Testing of core StudentVC features unrelated to X.509 or status lists (unless affected by regression).
*   Underlying infrastructure performance (network latency, server hardware limitations beyond application control).
*   Third-party CA operational security.

## 4. Testing Levels

*   **Unit Testing:** Continue adding tests for individual functions, especially for security-critical logic (e.g., signature verification, certificate parsing, status bit manipulation) and performance-optimized routines.
*   **Integration Testing:** Verify interactions between components (e.g., issuer generating status lists, verifier checking status, X.509 manager interacting with certificate store).
*   **End-to-End (E2E) Testing:** Simulate real-world scenarios using the existing test suite (`test_x509_e2e.py`) and potentially expand it to cover more complex security and performance edge cases.
*   **Security Testing:**
    *   **Static Analysis (SAST):** Use tools to scan code for potential security flaws.
    *   **Dynamic Analysis (DAST):** Probe running application endpoints for vulnerabilities.
    *   **Penetration Testing:** Simulate attacks to identify exploitable weaknesses (manual or automated).
    *   **Dependency Scanning:** Check third-party libraries for known vulnerabilities.
*   **Performance Testing:**
    *   **Load Testing:** Simulate expected user load to measure response times and resource usage.
    *   **Stress Testing:** Push the system beyond normal limits to find breaking points and assess recovery.
    *   **Soak Testing:** Run the system under moderate load for extended periods to detect memory leaks or performance degradation.
    *   **Profiling:** Analyze code execution to pinpoint performance bottlenecks.

## 5. Test Environment

*   **Development:** Local machines using `sqlite` and temporary certificates (as used in current `pytest` setup).
*   **Staging/Testing:** Dedicated environment closely mirroring production (e.g., Docker containers, PostgreSQL/MySQL database, realistic network setup, production-like certificates/CAs if possible). This environment will be used for security scans, performance tests, and final UAT.
*   **CI/CD:** GitHub Actions environment for running unit, integration, and basic E2E tests on pushes/PRs.

## 6. Test Data Requirements

*   Valid and invalid X.509 certificates (expired, revoked, wrong usage, self-signed, chain variations).
*   Test certificates with DIDs embedded in SubjectAlternativeName.
*   DID documents with X.509 certificate verification methods.
*   Certificate Signing Requests (CSRs) for testing CA-assisted DID creation.
*   Test challenges and signatures for challenge-response protocol testing.
*   Test credentials linked to various certificate types and DIDs.
*   Dual-proof presentations for OID4VC/OID4VP testing.
*   Large status lists for performance testing.
*   Data sets simulating various user loads and credential volumes.
*   Known vulnerability patterns for security testing tools.

## 7. Testing Tools

*   **Test Runner:** `pytest`
*   **Code Coverage:** `pytest-cov`
*   **Mocking:** `pytest-mock`
*   **Linters/Formatters:** `flake8`, `black`, `isort`, `mypy`
*   **SAST:** Bandit, SonarQube (or similar integrated into IDE/CI)
*   **DAST:** OWASP ZAP, Burp Suite (Community Edition)
*   **Dependency Scanning:** `safety`, GitHub Dependabot
*   **Performance Testing:** `locust`, `k6`, Python's `cProfile`
*   **CI/CD:** GitHub Actions

## 8. Test Execution Strategy

1.  **Continuous Testing:** Run unit, integration, linting, and basic security checks automatically via GitHub Actions on every push/PR.
2.  **HAVID Compliance Testing:**
    *   Test bidirectional linkage validation between X.509 certificates and DIDs.
    *   Test the challenge-response protocol for proving cryptographic control.
    *   Test certificate lifecycle monitoring and rekeying detection.
    *   Test CA-assisted DID creation from CSR key material.
    *   Verify compliance with all HAVID specification requirements.
3.  **OID4VC/OID4VP Integration Testing:**
    *   Test enhanced issuer metadata with X.509 certificate information.
    *   Test dual-proof credential offers and presentations.
    *   Test X.509 metadata embedding in verifiable credentials.
    *   Test verification of credentials using both DID and X.509 trust paths.
    *   Test selective disclosure of certificate attributes.
4.  **Phase 4 - Security Audit:**
    *   Execute SAST scans on the codebase.
    *   Perform manual code review focusing on security-critical sections (crypto, validation, auth).
    *   Run dependency scans.
    *   Conduct DAST/Penetration testing on the staging environment.
    *   Log all findings in the issue tracker.
    *   Implement fixes for identified vulnerabilities.
    *   Re-test to verify fixes.
5.  **Phase 4 - Performance Optimization:**
    *   Establish baseline performance metrics on the staging environment.
    *   Profile the application under load to identify bottlenecks.
    *   Implement optimizations.
    *   Re-run performance tests (load, stress, soak) to measure improvements against baseline and targets.
    *   Iterate on optimizations as needed.
6.  **Regression Testing:** Run the full E2E test suite (`test_x509_e2e.py` and potentially others) after security fixes and performance optimizations to ensure no functionality is broken.
7.  **Documentation Review:** Ensure all documentation (`README.md`, `x509_integration.md`, `testplan.md`) is accurate and reflects the final implementation.

## 9. New Test Cases

### 9.1. HAVID Compliance Test Cases

1. **Bidirectional Linkage Tests**
   * Test creating a certificate with a DID in SubjectAlternativeName.
   * Test creating a DID document with certificate verification method.
   * Test verification of bidirectional linkage via `verify_bidirectional_linkage()`.
   * Test finding a DID in a certificate's SubjectAlternativeName.
   * Test finding X.509 verification methods in a DID document.
   * Test negative cases (invalid linkage, missing DID, missing certificate).

2. **Challenge-Response Protocol Tests**
   * Test challenge generation and validation.
   * Test signing a challenge with X.509 private key.
   * Test signing a challenge with DID private key.
   * Test verifying X.509 signature.
   * Test verifying DID signature.
   * Test verifying dual control (both signatures valid).
   * Test negative cases (invalid signatures, expired challenges, replay attacks).

3. **Certificate Lifecycle Tests**
   * Test registering certificate-DID binding for monitoring.
   * Test detecting expired certificates.
   * Test detecting certificates expiring soon.
   * Test detecting rekeyed certificates.
   * Test invalidating bindings.
   * Test finding current binding for a DID.
   * Test periodic monitoring process.

4. **CA-Assisted DID Creation Tests**
   * Test creating a DID from a CSR.
   * Test creating a certificate with a DID in SubjectAlternativeName.
   * Test creating a DID document from a CSR.
   * Test adding a certificate to a DID document.
   * Test end-to-end CSR processing flow.
   * Test saving and loading DID documents.

### 9.2. API Endpoint Tests

1. **Challenge API Tests**
   * Test `/x509/challenge` endpoint generates valid challenges.
   * Test challenge expiration and replay prevention.

2. **Verification API Tests**
   * Test `/x509/verify-control` endpoint with valid credentials.
   * Test `/x509/verify-control` endpoint with invalid credentials.
   * Test `/x509/verify-binding` endpoint with valid bindings.
   * Test `/x509/verify-binding` endpoint with invalid bindings.

3. **DID Creation API Tests**
   * Test `/x509/create-from-csr` endpoint with valid CSR.
   * Test `/x509/create-from-csr` endpoint with invalid CSR.
   * Test `/x509/did-document/{did}` endpoint.

### 9.3. OID4VC/OID4VP Integration Tests

1. **OID4VC Tests**
   * Test enhancing issuer metadata with X.509 information.
   * Test creating dual-proof credential offers.
   * Test embedding X.509 metadata in credentials.

2. **OID4VP Tests**
   * Test verifying credentials with X.509 information.
   * Test creating presentations with dual proofs.
   * Test verifying presentations with dual proofs.
   * Test selective disclosure of certificate attributes.

## 10. Reporting and Metrics

*   **Test Execution Reports:** Generated by `pytest` (pass/fail counts).
*   **Coverage Reports:** Generated by `pytest-cov` (HTML and terminal output).
*   **Security Scan Reports:** Output from SAST, DAST, and dependency scanning tools, linked to issues.
*   **Performance Test Reports:** Output from load testing tools (response times, error rates, throughput), profiling data.
*   **Bug Tracking:** Use GitHub Issues, tagged appropriately (e.g., `bug`, `security`, `performance`, `phase-4`, `havid`, `oid4vc`).
*   **Key Metrics:** Code coverage percentage, number of open/closed security vulnerabilities (by severity), performance benchmark results (e.g., avg/p95 response time, requests per second).

## 11. Roles and Responsibilities

*   **Developer (AI Assistant & User):** Implement features, write unit/integration tests, fix bugs, implement optimizations, perform initial security reviews.
*   **QA/Test Lead (AI Assistant):** Define test strategy, create test plan, execute E2E/Security/Performance tests, report results, manage defects.
*   **Security Reviewer (Potentially External/Specialized):** May be involved for in-depth penetration testing or audit review if required.

## 12. Risks and Mitigation

| Risk                                         | Likelihood | Impact | Mitigation Strategy                                                                                                |
| :------------------------------------------- | :--------- | :----- | :----------------------------------------------------------------------------------------------------------------- |
| Undetected security vulnerabilities          | Medium     | High   | Multi-layered security testing (SAST, DAST, manual review, dependency scanning), use established crypto libraries. |
| Incomplete HAVID compliance                  | Low        | High   | Comprehensive testing against all specification requirements, formal verification review.                           |
| OID4VC/OID4VP integration issues             | Medium     | Medium | End-to-end testing of credential issuance and verification flows, component isolation tests.                       |
| Performance degradation after integration    | Medium     | Medium | Comprehensive performance testing (load, stress, profiling), establish baseline, set performance targets.         |
| Regression bugs introduced                   | Medium     | Medium | Maintain high test coverage (unit, integration, E2E), run regression suite frequently, especially after major changes. |
| Cryptographic vulnerabilities in protocols   | Low        | High   | Use established crypto libraries, peer review security-critical code, follow best practices.                        |
| Certificate lifecycle monitoring failures    | Low        | Medium | Automated testing of lifecycle events, monitoring of edge cases (near-expiry, rekeying).                            |
| Incomplete test coverage                     | Low        | Medium | Use code coverage tools, peer review of tests, focus testing on critical paths and security boundaries.          |
| Test environment drift                       | Low        | Medium | Use Infrastructure as Code (e.g., Docker Compose) for staging, automate environment setup/teardown.                |
| Flaky tests                                  | Medium     | Low    | Investigate and fix root causes of flaky tests promptly, isolate external dependencies using mocks.              |

## 13. Sign-off Criteria

*   All planned tests (unit, integration, E2E, security, performance) executed.
*   Code coverage meets or exceeds target (e.g., 85%).
*   All High/Critical severity security vulnerabilities fixed and verified.
*   HAVID specification requirements fully verified and compliant.
*   OID4VC/OID4VP integration features fully tested and working as expected.
*   Performance meets defined targets or regressions are justified/accepted.
*   All major bugs fixed and verified.
*   Test plan and results reviewed and approved.
*   Documentation updated and accurate.

## 14. Test Plan Maintenance

This test plan should be updated whenever:
- New features are added to the X.509 integration
- HAVID specification is updated or extended
- OID4VC/OID4VP standards evolve
- New security risks are identified
- Performance requirements change

Revisions should be tracked via Git version control, with each update properly documented. 