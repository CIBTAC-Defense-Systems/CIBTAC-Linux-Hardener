# CIBTAC Linux Hardener
A next-gen, modular Linux security distribution built in Rust, leveraging behavior-based detection, advanced sandboxing, real-time logging, and integrity monitoring. CIBTAC Linux Hardener aims to provide robust and adaptive security controls with military-level performance and scalability.

Overview

CIBTAC Linux Hardener is a custom, security-focused Linux distribution designed to provide a hardened operating system that leverages Rust for performance, security, and maintainability. CIBTAC Linux Hardener utilizes behavior-based detection, advanced sandboxing, and multi-layered security components to protect against emerging threats while delivering a stable, enterprise-ready solution.

Features

    Behavior-Based Detection Engine: Identifies anomalies and malicious behaviors through real-time monitoring of system activities.
    Advanced Sandboxing: Isolates applications to prevent system-wide compromises, especially for closed-source or untrusted software.
    Mandatory Access Control (MAC): Implements custom, tightly-restricted access controls based on predefined profiles.
    System Integrity Monitoring: Monitors files and directories for unauthorized changes, ensuring the system's state remains secure.
    Real-Time Logging & Alerts: Collects and displays security events and anomalies, allowing administrators to act on threats swiftly.
    Rust-Based Components: Rewritten from scratch in Rust, each component offers high performance, security, and modularity.

CIBTAC Linux Hardener aims to be a comprehensive All-In-One (AIO) solution while maintaining modularity for independent component development, testing, and upgrades.

Table of Contents

    Installation
    Components
        Behavior-Based Detection Engine
        Sandboxing Layer
        Mandatory Access Control (MAC)
        System Integrity Monitoring
        Logging & Alerts
    Usage
    Contributing
    License

Installation

To install CIBTAC Linux Hardener:

    Clone the repository:

git clone https://github.com/CIBTAC-Defense-Systems/CIBTAC Linux Hardener.git
cd CIBTAC Linux Hardener

Build the core components:

cargo build --release

Install and configure each module individually or deploy the entire AIO (All-In-One) package using the provided installer script:

    ./install.sh

    Follow the prompts to set up behavior-based detection, sandboxing, integrity monitoring, and logging.

    Note: CIBTAC Linux Hardener is currently available for x86_64 architectures.

Components
Behavior-Based Detection Engine

The behavior-based detection engine monitors the system in real-time for unusual behavior, such as unexpected file changes, abnormal network activity, and unusual process activities.

    Language: Rust
    Modules: Built-in anomaly detection, system call tracing, and custom rule sets
    Usage:

    sudo CIBTACLH-detect start

Sandboxing Layer

VerdadX uses a custom-built sandboxing system in Rust, providing application isolation at the process and file level. This sandboxing is especially useful for containing untrusted applications and closed-source software.

    Features: Resource limits, custom container profiles, network isolation
    Usage:

    sudo CIBTACLH-sandbox run <application>

Mandatory Access Control (MAC)

Custom MAC policies enforce strict access control based on application behavior and expected functionality. This includes restricting file access, network connections, and system calls based on predefined policies.

    Language: Rust, integrated with the Linux kernel
    Modules: Profile manager, policy enforcement, rule updater

System Integrity Monitoring

Using a file integrity monitoring system, VerdadX regularly scans critical directories and files to detect unauthorized modifications.

    Features: Hash-based verification, scheduled scans, and change alerts
    Usage:

    sudo CIBTACLH-integrity scan

Logging & Alerts

The logging system provides real-time insights and detailed logs from the detection, sandboxing, and integrity monitoring modules. It is essential for quickly diagnosing and acting on security threats.

    Modules: Log aggregator, alert engine, customizable alert thresholds
    Dashboard: A web-based or CLI dashboard to view security events and set alerts.

Usage

To start VerdadX Secure Linux in All-In-One mode, ensuring all modules are running and integrated:

    Start CIBTAC Linux Hardener in AIO mode:

sudo CIBTACLH start


View Logs & Alerts: Check real-time logs and set alert thresholds through the VerdadX dashboard:

    CIBTAC-logs view

Contributing

We welcome contributions from the community to help enhance VerdadX. Please check the CONTRIBUTING.md for details on our code of conduct, contribution guidelines, and submission process.


License

This project is licensed under the MIT License - see the LICENSE file for details.
Roadmap

CIBTAC Linux Hardener is in its initial phase, and upcoming releases will focus on:

    Enhanced dashboard with customizable alerting and monitoring
    Expanded behavior rule sets for comprehensive detection
    Additional MAC profiles to cover a wider range of applications

Stay updated with our changelog.
Acknowledgments

Special thanks to the Rust community and contributors who have helped develop libraries and frameworks essential to this project.

For more details, visit VerdadX Documentation or join our community forum at VerdadX Community.
