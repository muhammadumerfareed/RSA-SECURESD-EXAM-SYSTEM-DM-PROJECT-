# 🔐 Secure Exam Management System (EMS)

> **An End-to-End Encrypted Assessment Portal implementing the RSA Cryptosystem in C++.**

!<img width="1034" height="2020" alt="_C__Users_HP_OneDrive_Desktop_poster html (5)" src="https://github.com/user-attachments/assets/64e753ae-5a65-43e4-85ce-c531a455fb5b" />


![Language](https://img.shields.io/badge/Language-C++17-00599C?style=for-the-badge&logo=c%2B%2B)
![Security](https://img.shields.io/badge/Security-RSA_Encryption-red?style=for-the-badge&logo=lock)
![Course](https://img.shields.io/badge/Domain-Discrete_Mathematics-orange?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows_Console-0078D6?style=for-the-badge&logo=windows)

## 📖 Project Abstract

In the era of e-learning, database leaks are a major threat. This project introduces a **Cryptographically Secure Education Management System**. Unlike traditional portals where data is stored as plain text, this system ensures that **Exam Questions** and **Student Answers** are encrypted at rest and in transit.

It utilizes the **RSA (Rivest–Shamir–Adleman)** algorithm to perform asymmetric encryption. Even if the backend `.txt` database is compromised, the attacker will only retrieve "garbage" ciphertext, as the private keys remain isolated on the user's client side.

---

## 🧮 The Mathematical Backbone (Discrete Structures)

This project is a practical implementation of **Number Theory**. The security relies on the computational difficulty of factoring large integers.

### 1. Key Generation (Euler's Totient)
We generate two large prime numbers, $p$ and $q$.
* **Modulus:** $n = p \times q$
* **Totient:** $\phi(n) = (p-1) \times (q-1)$
* **Public Exponent ($e$):** Chosen such that $1 < e < \phi(n)$ and $gcd(e, \phi(n)) = 1$.
* **Private Key ($d$):** Calculated using the **Modular Multiplicative Inverse**:
    $$d \cdot e \equiv 1 \pmod{\phi(n)}$$

### 2. Encryption & Decryption (Modular Exponentiation)
The core `modPow()` function in the code implements this logic efficiently to prevent integer overflow:
* **Encryption:** $C = M^e \pmod n$
* **Decryption:** $M = C^d \pmod n$

### 3. Digital Signatures (Data Integrity)
To prevent "Man-in-the-Middle" attacks, the system implements digital signatures.
* The sender "signs" a hash of the message using their **Private Key ($d$)**.
* The receiver verifies it using the sender's **Public Key ($e$)**.
    $$Signature = Hash(Message)^d \pmod n$$

---

## 🛠️ System Architecture

The application is split into two distinct, isolated portals governed by **Role-Based Access Control (RBAC)**.

### 👨‍🏫 Teacher Portal (The Certificate Authority)
* **Classroom Management:** Create classes and generate unique "Join Codes".
* **Exam Creation:** Draft exams where content is immediately encrypted upon saving.
* **Key Distribution:** Acts as a secure channel to distribute the `Public Key (e, n)` to authorized students only.
* **Decryption:** Unlocks student submissions using the corresponding Private Key.

### 👨‍🎓 Student Portal (The Secure Client)
* **Secure Retrieval:** Receives encrypted exam papers.
* **Cracking Simulation:** Includes a **"Key Cracking Demo"** module that allows students to attempt to factorize $n$ to understand why small primes are insecure.
* **Encrypted Submission:** Answers are encrypted using the Teacher's Public Key before being written to the disk.

---

## 💻 Tech Stack & Implementation details

| Component | Technology | Implementation Detail |
| :--- | :--- | :--- |
| **Language** | C++ (Standard 17) | Core logic and memory management. |
| **UI Framework** | `<windows.h>` | Custom colors, cursor positioning, and ASCII dashboards. |
| **Database** | Custom File I/O | Persistent storage using CSV-style parsing (`strtok`). |
| **Cryptography** | `long long` Integers | Custom implementation of GCD and Extended Euclidean Algorithm. |

---

## 🚀 Key Features

### 🔐 1. End-to-End Encryption
Exam questions are never stored in plain text.
* *Input:* "What is the capital of France?"
* *Storage:* `843 192 443 12 998 ...` (Ciphertext)

### ✍️ 2. Digital Signatures
Ensures non-repudiation. When a student submits an exam, the system generates a hash of their answer and signs it. If the answer file is tampered with manually, the signature verification will fail.

### 🕵️ 3. The "Cracker" Module
An educational feature added for the Discrete Math presentation.
* It allows users to input a Public Key $(n, e)$.
* The system attempts a **Brute Force Factorization** to find $p$ and $q$.
* If successful, it mathematically derives the private key $d$, demonstrating the vulnerability of weak keys.

### 📦 4. Persistent Database
The system uses a custom file engine to ensure data survives after execution:
* `users.txt`: Stores hashed passwords and RSA Keypairs.
* `exams.txt`: Stores encrypted exam content.
* `assignments.txt`: Stores encrypted student answers.

---

## ⚙️ How to Run

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/muhammadumerfareed/RSA-SECURESD-EXAM-SYSTEM-DM-PROJECT-.git
    ```
2.  **Environment:**
    * You need a **Windows** environment (due to `<windows.h>`).
    * Use **Visual Studio** or **Dev-C++**.
3.  **Compile & Run:**
    * Compile `main.cpp`.
    * Ensure the `.txt` files (created automatically) are in the same directory.

---

## 📸 Screenshots

### 1. RSA Key Generation
*Automatic generation of primes p, q and calculation of keys.*
![Key Gen](https://via.placeholder.com/600x200?text=RSA+Key+Generation+Demo)

### 2. Encryption Demo
*Visualizing how ASCII characters transform into Ciphertext.*
![Encryption](https://via.placeholder.com/600x200?text=Encryption+Process+Visualized)

---

## 🏆 Credits

**Developed By:**
* **Muhammad Umer Fareed**
* **Muhammad Hamza Hassan**

**Supervised By:**
* **Mr. Waqas Ali**

**Course:**
* Discrete Mathematics 

---
<p align="center">
  <i>"Mathematics is the Queen of the Sciences, and Number Theory is the Queen of Mathematics." - Gauss</i>
</p>
