# Retrieving addresses of exported functions indirectly

Direct use of ‍‍‍‍`GetModuleHandle` and `GetProcAddress` in malware can cause it to be flagged as a malicious file.
Here is a simple example that retrieves the address of exported functions (using PEB and EAT).

- **Hides API from the IAT**

    ![image](/screenshots/screenshot_1.png)

- **Executes shellcode**

    ![image](/screenshots/screenshot_2.png)
