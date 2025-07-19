Kernel Shepherd is a research project and proof-of-concept implementation of Static Binary Rewriting and Program Shepherding for the Microsoft Windows kernel and Microsoft Windows Drivers (without source code). It is my old project from 2011.


Based on my paper "Securing The Kernel via Static Binary Rewriting and Program Shepherding" ( https://piotrbania.com/all/articles/pbania-securing-the-kernel2011.pdf ) , this project demonstrates how to instrument (statically) the Windows kernel binary to enforce fine-grained control flow monitoring and runtime execution policy enforcement.

## 💡 What It Does

* **Statically rewrites the Windows kernel image** (`ntoskrnl.exe`) or other drivers without SOURCE CODE to:

  * Inject custom instrumentation code
  * Preserve original logic and other important data (ie. relocation data)
* Implements **Program Shepherding**, tracking the **execution flow** of kernel code at runtime
* Enforces security policies such as:

  * Only allowing execution from known, trusted locations
  * Preventing control flow transfers to suspicious or unknown memory regions
* Detects control flow anomalies typically used in kernel-mode exploits or shellcode injections

---

## 🔬 Key Techniques

* **Static Binary Rewriting**
  Modifies the kernel binary offline, inserting monitoring and control logic directly into the code sections, while preserving relocation info and layout.

* **Program Shepherding**
  A runtime mechanism that monitors indirect control transfers (e.g., jumps, calls, returns) and validates them against predefined security policies.

* **Custom Rewriter Toolchain**
  Includes disassembler, binary rewritter, relocation-aware patching, and image reassembler.


Keep it mind this is project from 2011 :)
